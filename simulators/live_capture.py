"""
Real-Time Network Traffic Capture
==================================
Uses psutil to capture actual network traffic from the host machine every second.
Provides:
  - Per-second byte/packet deltas (throughput)
  - Active TCP/UDP connections (remote IPs, ports, protocols)
  - Interface info (WiFi name, IP address)
  - IoT-pipeline-compatible feature vectors for scoring
  - Self-learning baseline (first 30s) + Z-score anomaly detection
"""

import os
import sys
import psutil
import socket
import time
import threading
import numpy as np
from datetime import datetime
from collections import defaultdict

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ml_engine.drift_detector import DRIFT_FEATURES, compute_drift, DRIFT_NONE, DriftResult
from trust_engine.trust_scorer import map_severity
from config.device_profiles import is_internal_ip

# ─────────────────────────────────────────────
# PORT → PROTOCOL MAPPING (for display)
# ─────────────────────────────────────────────
PORT_PROTOCOL_MAP = {
    80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH",
    21: "FTP", 25: "SMTP", 110: "POP3", 143: "IMAP",
    993: "IMAPS", 995: "POP3S", 587: "SMTP", 3389: "RDP",
    8080: "HTTP-ALT", 8443: "HTTPS-ALT", 554: "RTSP",
    3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
    27017: "MongoDB", 445: "SMB", 139: "NetBIOS",
    5353: "mDNS", 1883: "MQTT", 8883: "MQTTS",
}


def _port_to_protocol(port, proto_type="TCP"):
    """Map a port number to a human-readable protocol name."""
    return PORT_PROTOCOL_MAP.get(port, f"{proto_type}/{port}")


class LiveNetworkCapture:
    """
    Captures real network traffic using psutil.
    Runs in a background thread, producing one snapshot per second.
    Includes self-learning baseline and anomaly scoring.
    """

    def __init__(self, max_snapshots=600, baseline_seconds=30):
        self.running = False
        self._thread = None
        self._lock = threading.Lock()
        self.max_snapshots = max_snapshots  # 10 minutes at 1/sec

        # ── State ──
        self._snapshots = []
        self._prev_io = None
        self._prev_nic_io = None
        self._tick_count = 0

        # ── Interface info ──
        self.interface_name = None
        self.interface_ip = None
        self._detect_active_interface()

        # ── Baseline / Scoring ──
        self.baseline_seconds = baseline_seconds
        self._baseline_features = []
        self._baseline_stats = None  # {feature: {mean, std}}
        self._ema_trust = None       # EMA smoothed trust score
        self._scored_windows = []    # Rolling buffer of scored results
        self.max_scored = 300

        # ── Alert feed ──
        self._alerts = []
        self.max_alerts = 200

    # ─────────────────────────────────────────
    # INTERFACE DETECTION
    # ─────────────────────────────────────────

    def _detect_active_interface(self):
        """Find the active network interface (prefer WiFi)."""
        try:
            stats = psutil.net_if_stats()
            addrs = psutil.net_if_addrs()

            # Priority: WiFi interfaces
            wifi_candidates = [
                "Wi-Fi", "WiFi", "wlan0", "wlan1",
                "Wireless Network Connection", "WLAN",
            ]
            for name in wifi_candidates:
                if name in stats and stats[name].isup and name in addrs:
                    for addr in addrs[name]:
                        if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                            self.interface_name = name
                            self.interface_ip = addr.address
                            return

            # Fallback: any active non-loopback interface
            for name, st in stats.items():
                if st.isup and "Loopback" not in name and name != "lo":
                    if name in addrs:
                        for addr in addrs[name]:
                            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                                self.interface_name = name
                                self.interface_ip = addr.address
                                return
        except Exception as e:
            print(f"[LiveCapture] Interface detection error: {e}")

    # ─────────────────────────────────────────
    # SNAPSHOT CAPTURE (1 per second)
    # ─────────────────────────────────────────

    def _take_snapshot(self):
        """Capture current network state — I/O counters + active connections."""
        now = datetime.now()

        # ── Network I/O Counters ──
        io = psutil.net_io_counters()
        nic_io = psutil.net_io_counters(pernic=True)

        # Global deltas
        d_sent = max(0, io.bytes_sent - self._prev_io.bytes_sent) if self._prev_io else 0
        d_recv = max(0, io.bytes_recv - self._prev_io.bytes_recv) if self._prev_io else 0
        d_pkts_sent = max(0, io.packets_sent - self._prev_io.packets_sent) if self._prev_io else 0
        d_pkts_recv = max(0, io.packets_recv - self._prev_io.packets_recv) if self._prev_io else 0

        # Per-interface deltas
        iface_sent = 0
        iface_recv = 0
        if self.interface_name and self.interface_name in nic_io:
            cur = nic_io[self.interface_name]
            if self._prev_nic_io and self.interface_name in self._prev_nic_io:
                prev = self._prev_nic_io[self.interface_name]
                iface_sent = max(0, cur.bytes_sent - prev.bytes_sent)
                iface_recv = max(0, cur.bytes_recv - prev.bytes_recv)

        self._prev_io = io
        self._prev_nic_io = nic_io

        # ── Active Connections ──
        connections = []
        proto_counts = defaultdict(int)
        remote_ips = set()
        remote_ports = set()
        external_count = 0
        app_protos = defaultdict(int)

        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.raddr:
                    proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                    rip = conn.raddr.ip
                    rport = conn.raddr.port
                    is_ext = not is_internal_ip(rip)
                    if is_ext:
                        external_count += 1

                    app_proto = _port_to_protocol(rport, proto)
                    app_protos[app_proto] += 1

                    connections.append({
                        "local_port": conn.laddr.port if conn.laddr else 0,
                        "remote_ip": rip,
                        "remote_port": rport,
                        "protocol": proto,
                        "app_protocol": app_proto,
                        "status": conn.status,
                        "pid": conn.pid,
                        "is_external": is_ext,
                    })
                    proto_counts[proto] += 1
                    remote_ips.add(rip)
                    remote_ports.add(rport)
        except (psutil.AccessDenied, PermissionError, OSError):
            pass

        self._tick_count += 1

        snapshot = {
            "timestamp": now.isoformat(),
            "tick": self._tick_count,
            "interface": self.interface_name or "unknown",
            "interface_ip": self.interface_ip or "unknown",

            # Throughput
            "bytes_sent_per_sec": d_sent,
            "bytes_recv_per_sec": d_recv,
            "packets_sent_per_sec": d_pkts_sent,
            "packets_recv_per_sec": d_pkts_recv,
            "iface_bytes_sent": iface_sent,
            "iface_bytes_recv": iface_recv,

            # Connection summary
            "active_connections": len(connections),
            "unique_remote_ips": len(remote_ips),
            "unique_remote_ports": len(remote_ports),
            "external_connections": external_count,
            "protocols": dict(proto_counts),
            "app_protocols": dict(app_protos),

            # Top connections (limit for transfer)
            "connections": sorted(
                connections,
                key=lambda c: c.get("is_external", False),
                reverse=True,
            )[:40],
        }

        with self._lock:
            self._snapshots.append(snapshot)
            if len(self._snapshots) > self.max_snapshots:
                self._snapshots = self._snapshots[-self.max_snapshots:]

        return snapshot

    # ─────────────────────────────────────────
    # FEATURE EXTRACTION (IoT-compatible)
    # ─────────────────────────────────────────

    def get_feature_vector(self, window_secs=5):
        """
        Extract IoT-pipeline-compatible features from recent snapshots.
        Aggregates the last `window_secs` seconds into one feature vector.
        """
        with self._lock:
            recent = self._snapshots[-window_secs:] if len(self._snapshots) >= window_secs else list(self._snapshots)

        if not recent:
            return None

        total_bytes_out = sum(s["bytes_sent_per_sec"] for s in recent)
        total_pkts_out = sum(s["packets_sent_per_sec"] for s in recent)

        all_ips = set()
        all_ports = set()
        all_protos = set()
        ext_count = 0
        total_conns = 0

        for s in recent:
            for c in s.get("connections", []):
                all_ips.add(c["remote_ip"])
                all_ports.add(c["remote_port"])
                all_protos.add(c["protocol"])
                total_conns += 1
                if c.get("is_external"):
                    ext_count += 1

        num_flows = max(1, total_conns // max(1, len(recent)))

        return {
            "total_bytes_out": float(total_bytes_out),
            "total_packets_out": float(total_pkts_out),
            "avg_bytes_per_flow": float(total_bytes_out / max(1, num_flows)),
            "num_flows": float(num_flows),
            "unique_dst_ips": float(len(all_ips)),
            "unique_dst_ports": float(len(all_ports)),
            "unique_protocols": float(len(all_protos)),
            "external_ratio": float(ext_count / max(1, total_conns)),
            "avg_duration": 1.0,
        }

    # ─────────────────────────────────────────
    # BASELINE + SCORING
    # ─────────────────────────────────────────

    def _build_baseline(self):
        """Build baseline stats from collected features."""
        if len(self._baseline_features) < self.baseline_seconds:
            return

        stats = {}
        for feat in DRIFT_FEATURES:
            values = [f[feat] for f in self._baseline_features if feat in f]
            if values:
                stats[feat] = {
                    "mean": float(np.mean(values)),
                    "std": max(float(np.std(values)), 1e-6),
                }

        self._baseline_stats = stats
        print(f"[LiveCapture] Baseline built from {len(self._baseline_features)} samples")
        for feat, s in stats.items():
            print(f"  {feat}: mean={s['mean']:.1f}  std={s['std']:.1f}")

    def score_current(self):
        """
        Score current traffic against the learned baseline.
        Returns trust score, anomaly score, drift info, severity.
        During baseline learning, returns progress info.
        """
        features = self.get_feature_vector(window_secs=5)
        if not features:
            return None

        # ── Still learning baseline? ──
        if self._baseline_stats is None:
            self._baseline_features.append(features)
            progress = len(self._baseline_features) / self.baseline_seconds

            if len(self._baseline_features) >= self.baseline_seconds:
                self._build_baseline()

            return {
                "status": "learning",
                "progress": round(min(1.0, progress), 2),
                "seconds_remaining": max(0, self.baseline_seconds - len(self._baseline_features)),
                "features": features,
            }

        # ── Score using Z-scores ──
        zscores = {}
        for feat in DRIFT_FEATURES:
            if feat in self._baseline_stats and feat in features:
                mean = self._baseline_stats[feat]["mean"]
                std = self._baseline_stats[feat]["std"]
                z = abs(features[feat] - mean) / std if std > 1e-9 else 0.0
                zscores[feat] = min(z, 100.0)

        avg_z = sum(zscores.values()) / max(1, len(zscores))

        # Map to anomaly score (0=normal, 1=fully anomalous)
        anomaly_score = min(1.0, avg_z / 5.0)

        # Drift classification
        if avg_z < 1.5:
            drift_class = "DRIFT_NONE"
            drift_penalty = 0
        elif avg_z < 3.0:
            drift_class = "DRIFT_MILD"
            drift_penalty = 10
        else:
            drift_class = "DRIFT_STRONG"
            drift_penalty = 20

        # Trust score
        anomaly_deduction = anomaly_score * 40
        trust_raw = max(0, min(100, 100 - anomaly_deduction - drift_penalty))

        # EMA smoothing
        alpha = 0.3
        if self._ema_trust is not None:
            trust_smoothed = alpha * trust_raw + (1 - alpha) * self._ema_trust
        else:
            trust_smoothed = trust_raw
        self._ema_trust = trust_smoothed

        severity = map_severity(trust_smoothed)

        top_drifters = sorted(zscores.items(), key=lambda x: x[1], reverse=True)[:3]

        result = {
            "status": "scoring",
            "trust_score": round(trust_smoothed, 1),
            "trust_score_raw": round(trust_raw, 1),
            "anomaly_score": round(anomaly_score, 3),
            "anomaly_deduction": round(anomaly_deduction, 1),
            "drift_class": drift_class,
            "drift_magnitude": round(avg_z, 2),
            "drift_deduction": drift_penalty,
            "severity": severity,
            "top_drifters": [(k, round(v, 2)) for k, v in top_drifters],
            "features": features,
            "zscores": {k: round(v, 2) for k, v in zscores.items()},
            "tick": self._tick_count,
        }

        # Store for history
        with self._lock:
            self._scored_windows.append(result)
            if len(self._scored_windows) > self.max_scored:
                self._scored_windows = self._scored_windows[-self.max_scored:]

            # Generate alerts for anomalies
            if severity in ("High", "Critical") or anomaly_score > 0.6:
                self._alerts.append({
                    "tick": self._tick_count,
                    "timestamp": datetime.now().isoformat(),
                    "severity": severity,
                    "trust_score": round(trust_smoothed, 1),
                    "anomaly_score": round(anomaly_score, 3),
                    "drift_class": drift_class,
                    "top_feature": top_drifters[0][0] if top_drifters else "unknown",
                    "top_zscore": round(top_drifters[0][1], 2) if top_drifters else 0,
                    "message": f"Anomalous traffic detected — {top_drifters[0][0]} Z={top_drifters[0][1]:.1f}" if top_drifters else "Anomaly detected",
                })
                if len(self._alerts) > self.max_alerts:
                    self._alerts = self._alerts[-self.max_alerts:]

        return result

    # ─────────────────────────────────────────
    # LIFECYCLE
    # ─────────────────────────────────────────

    def _capture_loop(self):
        """Background loop — one snapshot + one score per second."""
        while self.running:
            try:
                self._take_snapshot()
                self.score_current()  # Score every tick
            except Exception as e:
                print(f"[LiveCapture] Error: {e}")
            time.sleep(1)

    def start(self):
        """Start real-time capture."""
        if self.running:
            return
        self._detect_active_interface()
        self.running = True
        # Initialize previous counters
        self._prev_io = psutil.net_io_counters()
        self._prev_nic_io = psutil.net_io_counters(pernic=True)
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()
        print(f"[LiveCapture] Started on {self.interface_name} ({self.interface_ip})")

    def stop(self):
        """Stop capture."""
        self.running = False
        if self._thread:
            self._thread.join(timeout=3)
        print("[LiveCapture] Stopped")

    def reset(self):
        """Clear all data and re-learn baseline."""
        with self._lock:
            self._snapshots = []
            self._baseline_features = []
            self._baseline_stats = None
            self._scored_windows = []
            self._alerts = []
            self._ema_trust = None
            self._tick_count = 0
            self._prev_io = None
            self._prev_nic_io = None

    # ─────────────────────────────────────────
    # DATA ACCESS
    # ─────────────────────────────────────────

    def get_snapshots(self, last_n=60):
        with self._lock:
            return list(self._snapshots[-last_n:])

    def get_latest(self):
        with self._lock:
            return self._snapshots[-1] if self._snapshots else None

    def get_scored_history(self, last_n=100):
        with self._lock:
            return list(self._scored_windows[-last_n:])

    def get_alerts(self, last_n=50):
        with self._lock:
            return list(self._alerts[-last_n:])

    def get_status(self):
        baseline_status = self._baseline_stats is not None
        return {
            "running": self.running,
            "interface": self.interface_name,
            "interface_ip": self.interface_ip,
            "tick_count": self._tick_count,
            "baseline_ready": baseline_status,
            "baseline_progress": min(1.0, len(self._baseline_features) / self.baseline_seconds) if not baseline_status else 1.0,
            "baseline_seconds_remaining": max(0, self.baseline_seconds - len(self._baseline_features)) if not baseline_status else 0,
            "total_snapshots": len(self._snapshots),
            "total_alerts": len(self._alerts),
        }

