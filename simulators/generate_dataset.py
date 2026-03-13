"""
IoT Device Simulator — Generates synthetic network telemetry dataset.
Simulates normal (48 hrs) + attack (2 hrs) traffic for CCTV, Router, AccessController.
Output: data/full_dataset.csv, data/baseline_data.csv, data/attack_data.csv
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random
import os
import sys

# Resolve project root (one level up from simulators/)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
os.makedirs(DATA_DIR, exist_ok=True)

random.seed(42)
np.random.seed(42)

records = []

# ============================================
# BASE SETTINGS
# ============================================
base_time = datetime(2024, 1, 15, 0, 0, 0)  # Start: Jan 15, midnight

# ============================================
# PHASE 1: NORMAL TRAFFIC (48 HOURS)
# ============================================
# Each device generates 1 record per minute = 2880 records per device

print("=" * 50)
print("IoT Trust & Drift Analytics — Dataset Generator")
print("=" * 50)
print("\n[Phase 1] Generating normal traffic (48 hours)...")

# --- CCTV_01: Normal Behavior ---
# Streams video to NVR continuously
# High bandwidth, RTSP, port 554
for i in range(2880):  # 48 hours * 60 minutes
    timestamp = base_time + timedelta(minutes=i)
    hour = timestamp.hour

    # CCTV is more active during day (6 AM - 11 PM)
    if 6 <= hour <= 23:
        bytes_out = int(np.random.normal(170000, 20000))
        packets_out = int(np.random.normal(170, 20))
    else:
        bytes_out = int(np.random.normal(100000, 15000))
        packets_out = int(np.random.normal(100, 15))

    records.append({
        "device_id": "CCTV_01",
        "device_type": "CCTV",
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": "192.168.1.10",
        "dst_ip": "192.168.1.100",  # NVR server
        "protocol": "RTSP",
        "dst_port": 554,
        "bytes_out": max(bytes_out, 1000),
        "packets_out": max(packets_out, 10),
        "duration": 60,
        "direction": "outbound",
        "label": "normal"
    })

# --- Router_01: Normal Behavior ---
# DNS queries, small packets, periodic
for i in range(2880):
    timestamp = base_time + timedelta(minutes=i)

    bytes_out = int(np.random.normal(8000, 2000))
    packets_out = int(np.random.normal(15, 5))
    dst_ip = random.choice(["8.8.8.8", "8.8.4.4"])

    records.append({
        "device_id": "Router_01",
        "device_type": "Router",
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": "192.168.1.1",
        "dst_ip": dst_ip,
        "protocol": "DNS",
        "dst_port": 53,
        "bytes_out": max(bytes_out, 100),
        "packets_out": max(packets_out, 1),
        "duration": 1,
        "direction": "outbound",
        "label": "normal"
    })

# --- Access_01: Normal Behavior ---
# HTTPS auth requests every 5 minutes
for i in range(576):  # 48 hours * 12 per hour (every 5 min)
    timestamp = base_time + timedelta(minutes=i * 5)

    bytes_out = int(np.random.normal(2000, 500))
    packets_out = int(np.random.normal(5, 2))

    records.append({
        "device_id": "Access_01",
        "device_type": "AccessController",
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": "192.168.1.20",
        "dst_ip": "192.168.1.50",  # Auth server
        "protocol": "HTTPS",
        "dst_port": 443,
        "bytes_out": max(bytes_out, 100),
        "packets_out": max(packets_out, 1),
        "duration": 2,
        "direction": "outbound",
        "label": "normal"
    })

print(f"  Normal records generated: {len(records)}")

# ============================================
# PHASE 2: ATTACK TRAFFIC (2 HOURS)
# ============================================

print("\n[Phase 2] Generating attack traffic (2 hours)...")
attack_start = base_time + timedelta(hours=48)

# --- ATTACK 1: CCTV_01 Compromised ---
# Symptoms: traffic spike, SSH connections, new external IPs
for i in range(120):  # 2 hours = 120 minutes
    timestamp = attack_start + timedelta(minutes=i)

    # Data exfiltration: massive traffic to unknown external IPs
    records.append({
        "device_id": "CCTV_01",
        "device_type": "CCTV",
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": "192.168.1.10",
        "dst_ip": random.choice(["203.0.113.50", "198.51.100.25", "192.0.2.100"]),
        "protocol": "HTTPS",
        "dst_port": 443,
        "bytes_out": int(np.random.normal(850000, 100000)),  # 5x normal
        "packets_out": int(np.random.normal(800, 100)),
        "duration": 60,
        "direction": "outbound",
        "label": "attack_exfiltration"
    })

    # C2 channel: SSH connections (never seen on CCTV)
    if i % 5 == 0:
        records.append({
            "device_id": "CCTV_01",
            "device_type": "CCTV",
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": "192.168.1.10",
            "dst_ip": "203.0.113.50",  # C2 server
            "protocol": "SSH",
            "dst_port": 22,
            "bytes_out": int(np.random.normal(5000, 1000)),
            "packets_out": int(np.random.normal(10, 3)),
            "duration": 30,
            "direction": "outbound",
            "label": "attack_c2"
        })

# --- ATTACK 2: Router_01 Internal Scanning ---
# Symptoms: scanning internal network, unusual protocols
for i in range(120):
    timestamp = attack_start + timedelta(minutes=i)

    # Normal DNS continues (to hide attack)
    records.append({
        "device_id": "Router_01",
        "device_type": "Router",
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": "192.168.1.1",
        "dst_ip": "8.8.8.8",
        "protocol": "DNS",
        "dst_port": 53,
        "bytes_out": int(np.random.normal(8000, 2000)),
        "packets_out": int(np.random.normal(15, 5)),
        "duration": 1,
        "direction": "outbound",
        "label": "normal"
    })

    # Lateral movement scanning
    if i % 2 == 0:
        target_ip = f"192.168.1.{random.randint(2, 254)}"
        records.append({
            "device_id": "Router_01",
            "device_type": "Router",
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": "192.168.1.1",
            "dst_ip": target_ip,
            "protocol": "TCP",
            "dst_port": random.choice([22, 80, 443, 8080, 3389, 445]),
            "bytes_out": int(np.random.normal(500, 100)),
            "packets_out": int(np.random.normal(3, 1)),
            "duration": 1,
            "direction": "internal",
            "label": "attack_scanning"
        })

# --- Access_01: Stays Normal (no false alarm test) ---
for i in range(24):
    timestamp = attack_start + timedelta(minutes=i * 5)

    records.append({
        "device_id": "Access_01",
        "device_type": "AccessController",
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": "192.168.1.20",
        "dst_ip": "192.168.1.50",
        "protocol": "HTTPS",
        "dst_port": 443,
        "bytes_out": int(np.random.normal(2000, 500)),
        "packets_out": int(np.random.normal(5, 2)),
        "duration": 2,
        "direction": "outbound",
        "label": "normal"
    })

# ============================================
# SAVE DATASET
# ============================================

print("\n[Phase 3] Saving datasets...")

df = pd.DataFrame(records)
df = df.sort_values("timestamp").reset_index(drop=True)

# Save full dataset
full_path = os.path.join(DATA_DIR, "full_dataset.csv")
df.to_csv(full_path, index=False)

# Save normal only (for baseline training)
df_normal = df[df["label"] == "normal"]
baseline_path = os.path.join(DATA_DIR, "baseline_data.csv")
df_normal.to_csv(baseline_path, index=False)

# Save attack only (for testing)
df_attack = df[df["label"] != "normal"]
attack_path = os.path.join(DATA_DIR, "attack_data.csv")
df_attack.to_csv(attack_path, index=False)

# Print summary
print("\n" + "=" * 50)
print("DATASET SUMMARY")
print("=" * 50)
print(f"Total records   : {len(df)}")
print(f"Normal records  : {len(df_normal)}")
print(f"Attack records  : {len(df_attack)}")
print(f"\nRecords per device & label:")
print(df.groupby("device_id")["label"].value_counts().to_string())
print(f"\nTime range: {df['timestamp'].min()} to {df['timestamp'].max()}")
print(f"\nFiles saved to: {DATA_DIR}")
print(f"  [OK] full_dataset.csv     ({len(df)} rows)")
print(f"  [OK] baseline_data.csv    ({len(df_normal)} rows)")
print(f"  [OK] attack_data.csv      ({len(df_attack)} rows)")
print("=" * 50)

