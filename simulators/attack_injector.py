"""
Attack Injector — Generates realistic attack traffic for any device on demand.
Used by the API server for live demo injection.

Supports:
  CCTV       -> exfiltration, c2
  Router     -> lateral_scan, dns_tunnel
  AccessController -> credential_stuffing, exfiltration
"""

import pandas as pd
import numpy as np
import random
import os
import sys
from datetime import datetime, timedelta

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from config.device_profiles import is_internal_ip

# ─────────────────────────────────────────────
# ATTACK CATALOG
# ─────────────────────────────────────────────

ATTACK_CATALOG = {
    "CCTV": [
        {
            "id": "exfiltration",
            "name": "Data Exfiltration",
            "description": "Massive HTTPS uploads to unknown external IPs — 5x normal bandwidth",
            "mitre": "TA0010 — Exfiltration",
        },
        {
            "id": "c2",
            "name": "C2 Channel (SSH)",
            "description": "SSH connections to external C2 server — never seen on CCTV",
            "mitre": "TA0011 — Command & Control",
        },
    ],
    "Router": [
        {
            "id": "lateral_scan",
            "name": "Lateral Scanning",
            "description": "TCP scans on internal network — ports 22, 445, 3389, 8080",
            "mitre": "TA0007 — Discovery",
        },
        {
            "id": "dns_tunnel",
            "name": "DNS Tunneling",
            "description": "DNS queries with abnormally large payloads to unknown DNS server",
            "mitre": "TA0010 — Exfiltration over DNS",
        },
    ],
    "AccessController": [
        {
            "id": "credential_stuffing",
            "name": "Credential Stuffing",
            "description": "Burst of HTTPS auth requests — 10x normal frequency",
            "mitre": "TA0006 — Credential Access",
        },
        {
            "id": "exfiltration",
            "name": "Data Exfiltration",
            "description": "HTTPS uploads of badge logs to unknown external IP",
            "mitre": "TA0010 — Exfiltration",
        },
    ],
}

# Device source IPs
DEVICE_SRC_IPS = {
    "CCTV_01": "192.168.1.10",
    "Router_01": "192.168.1.1",
    "Access_01": "192.168.1.20",
}

# ─────────────────────────────────────────────
# ATTACK FLOW GENERATORS
# ─────────────────────────────────────────────

def _generate_cctv_exfiltration(device_id, start_time, duration_minutes=120):
    """CCTV compromised — massive data upload to external IPs."""
    flows = []
    src_ip = DEVICE_SRC_IPS.get(device_id, "192.168.1.10")
    for i in range(duration_minutes):
        ts = start_time + timedelta(minutes=i)
        flows.append({
            "device_id": device_id,
            "device_type": "CCTV",
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": src_ip,
            "dst_ip": random.choice(["203.0.113.50", "198.51.100.25", "192.0.2.100"]),
            "protocol": "HTTPS",
            "dst_port": 443,
            "bytes_out": int(np.random.normal(850000, 100000)),
            "packets_out": int(np.random.normal(800, 100)),
            "duration": 60,
            "direction": "outbound",
            "label": "attack_exfiltration",
        })
    return flows


def _generate_cctv_c2(device_id, start_time, duration_minutes=120):
    """CCTV compromised — SSH C2 channel + continued normal traffic."""
    flows = []
    src_ip = DEVICE_SRC_IPS.get(device_id, "192.168.1.10")
    for i in range(duration_minutes):
        ts = start_time + timedelta(minutes=i)
        # Normal RTSP continues (to make it realistic)
        flows.append({
            "device_id": device_id,
            "device_type": "CCTV",
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": src_ip,
            "dst_ip": "192.168.1.100",
            "protocol": "RTSP",
            "dst_port": 554,
            "bytes_out": int(np.random.normal(170000, 20000)),
            "packets_out": int(np.random.normal(170, 20)),
            "duration": 60,
            "direction": "outbound",
            "label": "normal",
        })
        # C2 SSH every 5 minutes
        if i % 5 == 0:
            flows.append({
                "device_id": device_id,
                "device_type": "CCTV",
                "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "src_ip": src_ip,
                "dst_ip": "203.0.113.50",
                "protocol": "SSH",
                "dst_port": 22,
                "bytes_out": int(np.random.normal(5000, 1000)),
                "packets_out": int(np.random.normal(10, 3)),
                "duration": 30,
                "direction": "outbound",
                "label": "attack_c2",
            })
    return flows


def _generate_router_lateral_scan(device_id, start_time, duration_minutes=120):
    """Router compromised — scanning internal network."""
    flows = []
    src_ip = DEVICE_SRC_IPS.get(device_id, "192.168.1.1")
    for i in range(duration_minutes):
        ts = start_time + timedelta(minutes=i)
        # Normal DNS continues
        flows.append({
            "device_id": device_id,
            "device_type": "Router",
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": src_ip,
            "dst_ip": "8.8.8.8",
            "protocol": "DNS",
            "dst_port": 53,
            "bytes_out": int(np.random.normal(8000, 2000)),
            "packets_out": int(np.random.normal(15, 5)),
            "duration": 1,
            "direction": "outbound",
            "label": "normal",
        })
        # Lateral scan every 2 minutes
        if i % 2 == 0:
            target_ip = f"192.168.1.{random.randint(2, 254)}"
            flows.append({
                "device_id": device_id,
                "device_type": "Router",
                "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "src_ip": src_ip,
                "dst_ip": target_ip,
                "protocol": "TCP",
                "dst_port": random.choice([22, 80, 443, 8080, 3389, 445]),
                "bytes_out": int(np.random.normal(500, 100)),
                "packets_out": int(np.random.normal(3, 1)),
                "duration": 1,
                "direction": "internal",
                "label": "attack_scanning",
            })
    return flows


def _generate_router_dns_tunnel(device_id, start_time, duration_minutes=120):
    """Router compromised — data exfiltration via DNS tunneling."""
    flows = []
    src_ip = DEVICE_SRC_IPS.get(device_id, "192.168.1.1")
    for i in range(duration_minutes):
        ts = start_time + timedelta(minutes=i)
        # Normal DNS
        flows.append({
            "device_id": device_id,
            "device_type": "Router",
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": src_ip,
            "dst_ip": "8.8.8.8",
            "protocol": "DNS",
            "dst_port": 53,
            "bytes_out": int(np.random.normal(8000, 2000)),
            "packets_out": int(np.random.normal(15, 5)),
            "duration": 1,
            "direction": "outbound",
            "label": "normal",
        })
        # DNS tunnel — large payloads to suspicious DNS server
        flows.append({
            "device_id": device_id,
            "device_type": "Router",
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": src_ip,
            "dst_ip": "198.51.100.53",
            "protocol": "DNS",
            "dst_port": 53,
            "bytes_out": int(np.random.normal(65000, 10000)),
            "packets_out": int(np.random.normal(50, 10)),
            "duration": 1,
            "direction": "outbound",
            "label": "attack_dns_tunnel",
        })
    return flows


def _generate_access_credential_stuffing(device_id, start_time, duration_minutes=120):
    """Access Controller — brute force credential stuffing."""
    flows = []
    src_ip = DEVICE_SRC_IPS.get(device_id, "192.168.1.20")
    for i in range(duration_minutes):
        ts = start_time + timedelta(minutes=i)
        # 10x normal frequency — every minute instead of every 5
        flows.append({
            "device_id": device_id,
            "device_type": "AccessController",
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": src_ip,
            "dst_ip": "192.168.1.50",
            "protocol": "HTTPS",
            "dst_port": 443,
            "bytes_out": int(np.random.normal(8000, 2000)),
            "packets_out": int(np.random.normal(20, 5)),
            "duration": 1,
            "direction": "outbound",
            "label": "attack_credential_stuffing",
        })
        # Also hitting external auth servers (shouldn't happen)
        if i % 3 == 0:
            flows.append({
                "device_id": device_id,
                "device_type": "AccessController",
                "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "src_ip": src_ip,
                "dst_ip": "203.0.113.99",
                "protocol": "HTTPS",
                "dst_port": 443,
                "bytes_out": int(np.random.normal(3000, 800)),
                "packets_out": int(np.random.normal(8, 3)),
                "duration": 1,
                "direction": "outbound",
                "label": "attack_credential_stuffing",
            })
    return flows


def _generate_access_exfiltration(device_id, start_time, duration_minutes=120):
    """Access Controller — exfiltrating badge/auth logs to external."""
    flows = []
    src_ip = DEVICE_SRC_IPS.get(device_id, "192.168.1.20")
    for i in range(duration_minutes):
        ts = start_time + timedelta(minutes=i)
        # Normal auth continues
        if i % 5 == 0:
            flows.append({
                "device_id": device_id,
                "device_type": "AccessController",
                "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "src_ip": src_ip,
                "dst_ip": "192.168.1.50",
                "protocol": "HTTPS",
                "dst_port": 443,
                "bytes_out": int(np.random.normal(2000, 500)),
                "packets_out": int(np.random.normal(5, 2)),
                "duration": 2,
                "direction": "outbound",
                "label": "normal",
            })
        # Exfiltration to external IP
        flows.append({
            "device_id": device_id,
            "device_type": "AccessController",
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": src_ip,
            "dst_ip": "198.51.100.77",
            "protocol": "HTTPS",
            "dst_port": 443,
            "bytes_out": int(np.random.normal(50000, 10000)),
            "packets_out": int(np.random.normal(40, 10)),
            "duration": 5,
            "direction": "outbound",
            "label": "attack_exfiltration",
        })
    return flows


# Map (device_type, attack_id) -> generator function
_GENERATORS = {
    ("CCTV", "exfiltration"): _generate_cctv_exfiltration,
    ("CCTV", "c2"): _generate_cctv_c2,
    ("Router", "lateral_scan"): _generate_router_lateral_scan,
    ("Router", "dns_tunnel"): _generate_router_dns_tunnel,
    ("AccessController", "credential_stuffing"): _generate_access_credential_stuffing,
    ("AccessController", "exfiltration"): _generate_access_exfiltration,
}


def get_device_type(device_id: str) -> str:
    """Derive device type from device_id."""
    if "CCTV" in device_id:
        return "CCTV"
    elif "Router" in device_id:
        return "Router"
    elif "Access" in device_id:
        return "AccessController"
    return "Unknown"


def generate_attack_flows(device_id: str, attack_type: str, start_time: datetime, duration_minutes: int = 120):
    """
    Generate attack flows for a device.
    Returns list of flow dicts ready to be appended to full_dataset.csv.
    """
    device_type = get_device_type(device_id)
    generator = _GENERATORS.get((device_type, attack_type))
    if generator is None:
        raise ValueError(f"Unknown attack: {device_type}/{attack_type}")
    return generator(device_id, start_time, duration_minutes)


# ─────────────────────────────────────────────
# FEATURE EXTRACTION FROM RAW FLOWS
# ─────────────────────────────────────────────

def extract_features(raw_df: pd.DataFrame) -> pd.DataFrame:
    """
    Extract hourly feature vectors from raw telemetry flows.
    This is the same logic that created the original feature_vectors.csv.
    
    Input:  raw_df with columns [device_id, device_type, timestamp, src_ip, dst_ip,
                                  protocol, dst_port, bytes_out, packets_out, duration, direction, label]
    Output: DataFrame with columns [device_id, window, total_bytes_out, total_packets_out,
                                     avg_bytes_per_flow, num_flows, unique_dst_ips, unique_dst_ports,
                                     unique_protocols, external_ratio, avg_duration]
    """
    df = raw_df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["window"] = df["timestamp"].dt.floor("h")
    df["is_external"] = df["dst_ip"].apply(lambda ip: 0 if is_internal_ip(str(ip)) else 1)

    grouped = df.groupby(["device_id", "window"])

    features = grouped.agg(
        total_bytes_out=("bytes_out", "sum"),
        total_packets_out=("packets_out", "sum"),
        avg_bytes_per_flow=("bytes_out", "mean"),
        num_flows=("bytes_out", "count"),
        unique_dst_ips=("dst_ip", "nunique"),
        unique_dst_ports=("dst_port", "nunique"),
        unique_protocols=("protocol", "nunique"),
        external_ratio=("is_external", "mean"),
        avg_duration=("duration", "mean"),
    ).reset_index()

    features = features.sort_values(["device_id", "window"]).reset_index(drop=True)
    return features

