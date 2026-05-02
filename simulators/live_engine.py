"""
Live Data Engine — Generates + scores telemetry windows in real-time.
Every tick (10 seconds), generates 1 new window per device, scores inline,
and stores in a rolling buffer. No full pipeline re-run needed.

Used by the API server for live demo mode.
"""

import os
import sys
import time
import random
import threading
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ml_engine.anomaly_detector import FEATURE_COLS
from ml_engine.drift_detector import compute_drift, DRIFT_FEATURES
from trust_engine.policy_engine import evaluate_policy
from trust_engine.trust_scorer import map_severity
from config.device_profiles import is_internal_ip
from simulators.attack_injector import ATTACK_CATALOG, get_device_type

# ─────────────────────────────────────────────
# DEVICE NORMAL TRAFFIC PATTERNS
# ─────────────────────────────────────────────

NORMAL_PATTERNS = {
    "CCTV_01": {
        "device_type": "CCTV",
        "src_ip": "192.168.1.10",
        "flows_per_window": 60,
        "flow_template": {
            "dst_ip": "192.168.1.100",
            "protocol": "RTSP",
            "dst_port": 554,
            "bytes_out_mean": 170000, "bytes_out_std": 20000,
            "packets_out_mean": 170, "packets_out_std": 20,
            "duration": 60,
            "direction": "outbound",
        },
    },
    "Router_01": {
        "device_type": "Router",
        "src_ip": "192.168.1.1",
        "flows_per_window": 60,
        "flow_template": {
            "dst_ip_choices": ["8.8.8.8", "8.8.4.4"],
            "protocol": "DNS",
            "dst_port": 53,
            "bytes_out_mean": 8000, "bytes_out_std": 2000,
            "packets_out_mean": 15, "packets_out_std": 5,
            "duration": 1,
            "direction": "outbound",
        },
    },
    "Access_01": {
        "device_type": "AccessController",
        "src_ip": "192.168.1.20",
        "flows_per_window": 12,
        "flow_template": {
            "dst_ip": "192.168.1.50",
            "protocol": "HTTPS",
            "dst_port": 443,
            "bytes_out_mean": 2000, "bytes_out_std": 500,
            "packets_out_mean": 5, "packets_out_std": 2,
            "duration": 2,
            "direction": "outbound",
        },
    },
}

# Attack flow patterns (per-minute flows when attack is active)
ATTACK_PATTERNS = {
    ("CCTV", "exfiltration"): {
        "flows": [
            {"dst_ip_choices": ["203.0.113.50", "198.51.100.25", "192.0.2.100"],
             "protocol": "HTTPS", "dst_port": 443,
             "bytes_out_mean": 850000, "bytes_out_std": 100000,
             "packets_out_mean": 800, "packets_out_std": 100,
             "duration": 60, "direction": "outbound", "label": "attack_exfiltration"},
        ],
        "flows_per_window": 60,
    },
    ("CCTV", "c2"): {
        "flows": [
            # Normal RTSP continues
            {"dst_ip": "192.168.1.100", "protocol": "RTSP", "dst_port": 554,
             "bytes_out_mean": 170000, "bytes_out_std": 20000,
             "packets_out_mean": 170, "packets_out_std": 20,
             "duration": 60, "direction": "outbound", "label": "normal"},
            # C2 SSH
            {"dst_ip": "203.0.113.50", "protocol": "SSH", "dst_port": 22,
             "bytes_out_mean": 5000, "bytes_out_std": 1000,
             "packets_out_mean": 10, "packets_out_std": 3,
             "duration": 30, "direction": "outbound", "label": "attack_c2"},
        ],
        "flows_per_window": 72,  # 60 normal + 12 C2
    },
    ("Router", "lateral_scan"): {
        "flows": [
            # Normal DNS
            {"dst_ip_choices": ["8.8.8.8", "8.8.4.4"], "protocol": "DNS", "dst_port": 53,
             "bytes_out_mean": 8000, "bytes_out_std": 2000,
             "packets_out_mean": 15, "packets_out_std": 5,
             "duration": 1, "direction": "outbound", "label": "normal"},
            # Lateral scan
            {"dst_ip_random_internal": True, "protocol": "TCP",
             "dst_port_choices": [22, 80, 443, 8080, 3389, 445],
             "bytes_out_mean": 500, "bytes_out_std": 100,
             "packets_out_mean": 3, "packets_out_std": 1,
             "duration": 1, "direction": "internal", "label": "attack_scanning"},
        ],
        "flows_per_window": 90,  # 60 normal + 30 scan
    },
    ("Router", "dns_tunnel"): {
        "flows": [
            # Normal DNS
            {"dst_ip_choices": ["8.8.8.8", "8.8.4.4"], "protocol": "DNS", "dst_port": 53,
             "bytes_out_mean": 8000, "bytes_out_std": 2000,
             "packets_out_mean": 15, "packets_out_std": 5,
             "duration": 1, "direction": "outbound", "label": "normal"},
            # DNS tunnel
            {"dst_ip": "198.51.100.53", "protocol": "DNS", "dst_port": 53,
             "bytes_out_mean": 65000, "bytes_out_std": 10000,
             "packets_out_mean": 50, "packets_out_std": 10,
             "duration": 1, "direction": "outbound", "label": "attack_dns_tunnel"},
        ],
        "flows_per_window": 120,  # 60 normal + 60 tunnel
    },
    ("AccessController", "credential_stuffing"): {
        "flows": [
            # High-frequency auth
            {"dst_ip": "192.168.1.50", "protocol": "HTTPS", "dst_port": 443,
             "bytes_out_mean": 8000, "bytes_out_std": 2000,
             "packets_out_mean": 20, "packets_out_std": 5,
             "duration": 1, "direction": "outbound", "label": "attack_credential_stuffing"},
            # External auth (shouldn't happen)
            {"dst_ip": "203.0.113.99", "protocol": "HTTPS", "dst_port": 443,
             "bytes_out_mean": 3000, "bytes_out_std": 800,
             "packets_out_mean": 8, "packets_out_std": 3,
             "duration": 1, "direction": "outbound", "label": "attack_credential_stuffing"},
        ],
        "flows_per_window": 80,  # 60 stuffing + 20 external
    },
    ("AccessController", "exfiltration"): {
        "flows": [
            # Normal auth continues
            {"dst_ip": "192.168.1.50", "protocol": "HTTPS", "dst_port": 443,
             "bytes_out_mean": 2000, "bytes_out_std": 500,
             "packets_out_mean": 5, "packets_out_std": 2,
             "duration": 2, "direction": "outbound", "label": "normal"},
            # Exfiltration
            {"dst_ip": "198.51.100.77", "protocol": "HTTPS", "dst_port": 443,
             "bytes_out_mean": 50000, "bytes_out_std": 10000,
             "packets_out_mean": 40, "packets_out_std": 10,
             "duration": 5, "direction": "outbound", "label": "attack_exfiltration"},
        ],
        "flows_per_window": 72,  # 12 normal + 60 exfil
    },
}


def _generate_flow(template, device_id, device_type, src_ip, timestamp):
    """Generate a single flow from a template."""
    # Determine destination IP
    if template.get("dst_ip_random_internal"):
        dst_ip = f"192.168.1.{random.randint(2, 254)}"
    elif "dst_ip_choices" in template:
        dst_ip = random.choice(template["dst_ip_choices"])
    else:
        dst_ip = template["dst_ip"]

    # Determine destination port
    if "dst_port_choices" in template:
        dst_port = random.choice(template["dst_port_choices"])
    else:
        dst_port = template["dst_port"]

    return {
        "device_id": device_id,
        "device_type": device_type,
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": template["protocol"],
        "dst_port": dst_port,
        "bytes_out": max(1, int(np.random.normal(template["bytes_out_mean"], template["bytes_out_std"]))),
        "packets_out": max(1, int(np.random.normal(template["packets_out_mean"], template["packets_out_std"]))),
        "duration": template["duration"],
        "direction": template["direction"],
        "label": template.get("label", "normal"),
    }


def _extract_features_from_flows(flows):
    """Extract a single feature vector from a list of flow dicts."""
    if not flows:
        return None
    df = pd.DataFrame(flows)
    df["is_external"] = df["dst_ip"].apply(lambda ip: 0 if is_internal_ip(str(ip)) else 1)

    return {
        "total_bytes_out": float(df["bytes_out"].sum()),
        "total_packets_out": float(df["packets_out"].sum()),
        "avg_bytes_per_flow": float(df["bytes_out"].mean()),
        "num_flows": float(len(df)),
        "unique_dst_ips": float(df["dst_ip"].nunique()),
        "unique_dst_ports": float(df["dst_port"].nunique()),
        "unique_protocols": float(df["protocol"].nunique()),
        "external_ratio": float(df["is_external"].mean()),
        "avg_duration": float(df["duration"].mean()),
    }


# ─────────────────────────────────────────────
# LIVE ENGINE CLASS
# ─────────────────────────────────────────────

class LiveEngine:
    """
    Generates + scores telemetry data in real-time.
    Runs in a background thread, producing one window per device every tick.
    """

    def __init__(self):
        self.running = False
        self.tick_interval = 10  # seconds between windows
        self._thread = None
        self._lock = threading.Lock()

        # State
        self.windows = []           # Rolling buffer of scored windows
        self.max_windows = 200      # Keep last 200 windows
        self.current_time = datetime(2024, 1, 15, 0, 0, 0)  # Simulated clock
        self.tick_count = 0
        self.active_attacks = {}    # {device_id: {"attack_type": ..., "attack_name": ..., "started_tick": ...}}

        # Live stats
        self.unknown_ips_detected = []   # List of {device_id, ip, timestamp}
        self.anomalous_windows = []      # List of anomalous window summaries
        self.protocol_violations = []    # List of protocol violation events

        # ML models (trained on init)
        self.models = {}        # {device_type: {"model": IsolationForest, "scaler": StandardScaler}}
        self.baseline_stats = {}  # {device_id: {feature: {mean, std}}}
        self.ema_state = {}     # {device_id: last_smoothed_score}

        # Train on startup
        self._train_models()

    def _train_models(self):
        """Train Isolation Forest models from baseline feature vectors."""
        DATA_DIR = os.path.join(PROJECT_ROOT, "data")
        feat_path = os.path.join(DATA_DIR, "feature_vectors_original.csv")
        if not os.path.exists(feat_path):
            feat_path = os.path.join(DATA_DIR, "feature_vectors.csv")

        df = pd.read_csv(feat_path)
        if "window_start" in df.columns:
            df = df.rename(columns={"window_start": "window"})
        df["window"] = pd.to_datetime(df["window"])

        # Add device_type
        if "device_type" not in df.columns:
            df["device_type"] = df["device_id"].apply(get_device_type)

        # Use first 48 hours as baseline
        cutoff = df["window"].min() + pd.Timedelta(hours=48)
        baseline = df[df["window"] < cutoff]

        # Compute baseline stats for drift detection
        for device_id in baseline["device_id"].unique():
            dev_data = baseline[baseline["device_id"] == device_id]
            stats = {}
            for feat in FEATURE_COLS:
                stats[feat] = {
                    "mean": float(dev_data[feat].mean()),
                    "std": float(dev_data[feat].std()) if dev_data[feat].std() > 0 else 1e-6,
                }
            self.baseline_stats[device_id] = stats

        # Train per-device-type Isolation Forest
        for device_type in baseline["device_type"].unique():
            type_data = baseline[baseline["device_type"] == device_type]
            X = type_data[FEATURE_COLS].values

            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)

            model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
            model.fit(X_scaled)

            self.models[device_type] = {"model": model, "scaler": scaler}

        # Also compute normalization bounds from baseline for anomaly_score
        all_X = baseline[FEATURE_COLS].values
        # We'll normalize per-type instead
        self._score_bounds = {}
        for device_type, m in self.models.items():
            type_data = baseline[baseline["device_type"] == device_type]
            X = type_data[FEATURE_COLS].values
            X_scaled = m["scaler"].transform(X)
            raw = m["model"].decision_function(X_scaled)
            self._score_bounds[device_type] = {"min": float(raw.min()), "max": float(raw.max())}

        print(f"[LiveEngine] Models trained: {list(self.models.keys())}")
        print(f"[LiveEngine] Baseline stats for: {list(self.baseline_stats.keys())}")

    def _score_single_window(self, device_id, device_type, features, raw_flows, window_str):
        """Score a single window inline — anomaly + drift + policy + trust."""

        # 1. Anomaly score (Isolation Forest)
        if device_type in self.models:
            m = self.models[device_type]
            X = np.array([[features[f] for f in FEATURE_COLS]])
            X_scaled = m["scaler"].transform(X)
            raw_score = float(m["model"].decision_function(X_scaled)[0])
            is_anomaly = int(m["model"].predict(X_scaled)[0] == -1)

            # Normalize to 0-1 using baseline bounds (with some margin)
            bounds = self._score_bounds.get(device_type, {"min": -0.5, "max": 0.5})
            mn, mx = bounds["min"] - 0.1, bounds["max"] + 0.1
            anomaly_score = max(0, min(1, 1 - (raw_score - mn) / (mx - mn + 1e-10)))
        else:
            anomaly_score = 0.0
            is_anomaly = 0

        # 2. Drift detection
        if device_id in self.baseline_stats:
            drift_result = compute_drift(device_id, window_str, features, self.baseline_stats[device_id])
        else:
            from ml_engine.drift_detector import DriftResult, DRIFT_NONE
            drift_result = DriftResult(device_id=device_id, window_start=window_str,
                                        drift_class=DRIFT_NONE, drift_magnitude=0, risk_level="LOW")

        # 3. Policy evaluation
        policy_result = evaluate_policy(device_id, device_type, window_str, features, raw_flows)

        # 4. Trust score
        anomaly_deduction = anomaly_score * 40
        drift_deduction = drift_result.penalty
        policy_deduction = policy_result.penalty
        trust_score_raw = max(0, min(100, 100 - anomaly_deduction - drift_deduction - policy_deduction))

        # 5. EMA smoothing
        alpha = 0.3
        if device_id in self.ema_state:
            trust_score_smoothed = alpha * trust_score_raw + (1 - alpha) * self.ema_state[device_id]
        else:
            trust_score_smoothed = trust_score_raw
        self.ema_state[device_id] = trust_score_smoothed

        severity = map_severity(trust_score_smoothed)

        # Track unknown IPs
        from config.device_profiles import get_profile
        profile = get_profile(device_type)
        if profile:
            observed_ips = set(f["dst_ip"] for f in raw_flows)
            unknown = [ip for ip in observed_ips if ip not in profile["allowed_dst_ips"] and not is_internal_ip(ip)]
            for ip in unknown:
                self.unknown_ips_detected.append({
                    "device_id": device_id,
                    "ip": ip,
                    "timestamp": window_str,
                    "tick": self.tick_count,
                })

        # Track anomalous windows
        if is_anomaly or severity in ["High", "Critical"]:
            self.anomalous_windows.append({
                "device_id": device_id,
                "window": window_str,
                "trust_score": round(trust_score_smoothed, 1),
                "severity": severity,
                "anomaly_score": round(anomaly_score, 3),
                "tick": self.tick_count,
            })

        # Track protocol violations
        if policy_result.violation_types:
            self.protocol_violations.append({
                "device_id": device_id,
                "window": window_str,
                "violations": policy_result.violations,
                "violation_types": policy_result.violation_types,
                "tick": self.tick_count,
            })

        return {
            "device_id": device_id,
            "device_type": device_type,
            "window": window_str,
            "tick": self.tick_count,
            "trust_score_raw": round(trust_score_raw, 1),
            "trust_score_smoothed": round(trust_score_smoothed, 1),
            "severity": severity,
            "anomaly_score": round(anomaly_score, 3),
            "is_anomaly": is_anomaly,
            "anomaly_deduction": round(anomaly_deduction, 1),
            "drift_class": drift_result.drift_class,
            "drift_magnitude": round(drift_result.drift_magnitude, 2),
            "drift_deduction": drift_deduction,
            "policy_status": policy_result.status,
            "policy_violations": "; ".join(policy_result.violations) if policy_result.violations else "none",
            "policy_deduction": policy_deduction,
            "top_drifters": str(drift_result.top_drifters),
            # Metadata for graphs
            "total_bytes_out": features["total_bytes_out"],
            "total_packets_out": features["total_packets_out"],
            "unique_dst_ips": features["unique_dst_ips"],
            "external_ratio": features["external_ratio"],
            "num_flows": features["num_flows"],
        }

    def _generate_and_score_tick(self):
        """Generate + score one window per device."""
        device_ids = list(NORMAL_PATTERNS.keys())
        tick_results = []

        for device_id in device_ids:
            pattern = NORMAL_PATTERNS[device_id]
            device_type = pattern["device_type"]
            src_ip = pattern["src_ip"]

            # Check if this device has an active attack
            attack_info = self.active_attacks.get(device_id)

            if attack_info:
                # Generate ATTACK flows
                attack_key = (device_type, attack_info["attack_type"])
                attack_pattern = ATTACK_PATTERNS.get(attack_key)
                if attack_pattern:
                    flows = []
                    n_flows = attack_pattern["flows_per_window"]
                    templates = attack_pattern["flows"]
                    for i in range(n_flows):
                        template = templates[i % len(templates)]
                        ts = self.current_time + timedelta(minutes=i)
                        flows.append(_generate_flow(template, device_id, device_type, src_ip, ts))
                else:
                    flows = self._generate_normal_flows(device_id)
            else:
                # Generate NORMAL flows
                flows = self._generate_normal_flows(device_id)

            # Extract features
            features = _extract_features_from_flows(flows)
            if features is None:
                continue

            # Score
            window_str = self.current_time.strftime("%Y-%m-%d %H:%M:%S")
            result = self._score_single_window(device_id, device_type, features, flows, window_str)
            tick_results.append(result)

        return tick_results

    def _generate_normal_flows(self, device_id):
        """Generate normal traffic flows for a device."""
        pattern = NORMAL_PATTERNS[device_id]
        device_type = pattern["device_type"]
        src_ip = pattern["src_ip"]
        template = pattern["flow_template"]
        n_flows = pattern["flows_per_window"]

        flows = []
        for i in range(n_flows):
            ts = self.current_time + timedelta(minutes=i)
            flows.append(_generate_flow(template, device_id, device_type, src_ip, ts))
        return flows

    def _tick(self):
        """Execute one tick — generate + score + store."""
        with self._lock:
            results = self._generate_and_score_tick()
            self.windows.extend(results)

            # Trim rolling buffer
            if len(self.windows) > self.max_windows:
                self.windows = self.windows[-self.max_windows:]
            if len(self.unknown_ips_detected) > 500:
                self.unknown_ips_detected = self.unknown_ips_detected[-500:]
            if len(self.anomalous_windows) > 500:
                self.anomalous_windows = self.anomalous_windows[-500:]
            if len(self.protocol_violations) > 500:
                self.protocol_violations = self.protocol_violations[-500:]

            self.current_time += timedelta(hours=1)  # Each tick = 1 simulated hour
            self.tick_count += 1

    def _run_loop(self):
        """Background loop."""
        while self.running:
            self._tick()
            time.sleep(self.tick_interval)

    def start(self, tick_interval=10):
        """Start live data generation."""
        if self.running:
            return
        self.tick_interval = tick_interval
        self.running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        print(f"[LiveEngine] Started — generating data every {tick_interval}s")
        # First tick runs automatically in the background thread — don't block here

    def stop(self):
        """Stop live data generation."""
        self.running = False
        if self._thread:
            self._thread.join(timeout=2)
        print("[LiveEngine] Stopped")

    def inject_attack(self, device_id, attack_type):
        """Start an attack on a device."""
        device_type = get_device_type(device_id)
        attack_name = next(
            (a["name"] for a in ATTACK_CATALOG.get(device_type, []) if a["id"] == attack_type),
            attack_type,
        )
        with self._lock:
            self.active_attacks[device_id] = {
                "attack_type": attack_type,
                "attack_name": attack_name,
                "device_type": device_type,
                "started_tick": self.tick_count,
            }
        # Schedule tick in background thread so we don't block the caller
        threading.Thread(target=self._tick, daemon=True).start()
        return {"device_id": device_id, "attack_type": attack_type, "attack_name": attack_name}

    def clear_attack(self, device_id):
        """Stop attack on a device."""
        with self._lock:
            if device_id in self.active_attacks:
                del self.active_attacks[device_id]
        threading.Thread(target=self._tick, daemon=True).start()

    def reset(self):
        """Clear everything — stop all attacks, clear history."""
        with self._lock:
            self.active_attacks = {}
            self.windows = []
            self.unknown_ips_detected = []
            self.anomalous_windows = []
            self.protocol_violations = []
            self.ema_state = {}
            self.current_time = datetime(2024, 1, 15, 0, 0, 0)
            self.tick_count = 0
        threading.Thread(target=self._tick, daemon=True).start()

    # ── Data Access ──

    def _get_latest_nolock(self):
        """Get latest window per device — caller must hold self._lock."""
        if not self.windows:
            return {}
        latest = {}
        for w in reversed(self.windows):
            did = w["device_id"]
            if did not in latest:
                latest[did] = w
            if len(latest) >= 3:
                break
        return latest

    def get_latest(self):
        """Get latest window per device."""
        with self._lock:
            return self._get_latest_nolock()

    def get_timeline(self, last_n=100):
        """Get last N windows."""
        with self._lock:
            return list(self.windows[-last_n:])

    def get_live_stats(self):
        """Get summary stats for the live dashboard — no deadlock."""
        with self._lock:
            # Use nolock version since we already hold the lock
            latest = self._get_latest_nolock()
            if not latest:
                return {
                    "tick_count": self.tick_count,
                    "running": self.running,
                    "devices": [],
                    "active_attacks": dict(self.active_attacks),
                    "total_anomalous": len(self.anomalous_windows),
                    "total_unknown_ips": len(self.unknown_ips_detected),
                    "total_violations": len(self.protocol_violations),
                }

            devices = []
            for dev_id, w in latest.items():
                devices.append({
                    "device_id": dev_id,
                    "device_type": w["device_type"],
                    "trust_score": w["trust_score_smoothed"],
                    "severity": w["severity"],
                    "anomaly_score": w["anomaly_score"],
                    "is_anomaly": w["is_anomaly"],
                    "total_bytes_out": w["total_bytes_out"],
                    "unique_dst_ips": w["unique_dst_ips"],
                    "external_ratio": w["external_ratio"],
                })

            return {
                "tick_count": self.tick_count,
                "current_time": self.current_time.isoformat(),
                "running": self.running,
                "devices": devices,
                "active_attacks": dict(self.active_attacks),
                "total_anomalous": len(self.anomalous_windows),
                "total_unknown_ips": len(self.unknown_ips_detected),
                "total_violations": len(self.protocol_violations),
            }

    def get_anomaly_feed(self, last_n=50):
        """Get recent anomalous events."""
        with self._lock:
            return list(self.anomalous_windows[-last_n:])

    def get_unknown_ips(self, last_n=50):
        """Get recently detected unknown IPs."""
        with self._lock:
            return list(self.unknown_ips_detected[-last_n:])

    def get_violations(self, last_n=50):
        """Get recent policy violations."""
        with self._lock:
            return list(self.protocol_violations[-last_n:])

