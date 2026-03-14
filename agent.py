"""
agent.py — Run this on each phone (Termux / any Python 3)
==========================================================
Install:
    pkg install python          # Termux
    pip install requests

Run (normal mode):
    python agent.py --role CCTV_01   --server http://LAPTOP_IP:8002

Run (malicious mode — phone sends attack traffic):
    python agent.py --role CCTV_01   --mode malicious --server http://LAPTOP_IP:8002

Available roles: CCTV_01, Router_01, Access_01
"""

import requests, time, random, argparse
from datetime import datetime

parser = argparse.ArgumentParser(description="IoT Trust-Drift Phone Agent")
parser.add_argument('--role',   choices=['CCTV_01', 'Access_01', 'Router_01'], required=True,
                    help="Which IoT device this phone pretends to be")
parser.add_argument('--mode',   choices=['normal', 'malicious'], default='normal',
                    help="normal = stay in baseline, malicious = inject attack patterns")
parser.add_argument('--server', required=True,
                    help="Laptop backend URL e.g. http://192.168.1.5:8002")
args = parser.parse_args()

SERVER = args.server.rstrip('/')

# ── Baseline feature ranges per device role ───────────────
# (tuned to match feature_vectors.csv baseline distribution)
BASELINES = {
    'CCTV_01':   dict(bytes_out=(20000, 30000), packets=(40, 70),
                      flows=(10, 14), dst_ips=1, dst_ports=1,
                      protocols=1, ext_ratio=0.0, duration=2.0),
    'Access_01': dict(bytes_out=(18000, 28000), packets=(45, 70),
                      flows=(10, 13), dst_ips=1, dst_ports=1,
                      protocols=1, ext_ratio=0.0, duration=2.0),
    'Router_01': dict(bytes_out=(50000, 90000), packets=(100, 200),
                      flows=(20, 40), dst_ips=5, dst_ports=3,
                      protocols=2, ext_ratio=0.3, duration=1.5),
}


def collect(role: str, mode: str) -> dict:
    """Build one telemetry window based on role + mode."""
    b = BASELINES[role]

    total_bytes_out    = random.uniform(*b['bytes_out'])
    total_packets_out  = random.randint(*b['packets'])
    num_flows          = random.randint(*b['flows'])
    avg_bytes_per_flow = total_bytes_out / num_flows
    unique_dst_ips     = b['dst_ips']
    unique_dst_ports   = b['dst_ports']
    unique_protocols   = b['protocols']
    external_ratio     = b['ext_ratio']
    avg_duration       = b['duration']

    if mode == 'malicious':
        if role == 'CCTV_01':
            # Port scan + data exfiltration
            total_bytes_out   *= random.uniform(8, 20)
            unique_dst_ips     = random.randint(20, 80)
            unique_dst_ports   = random.randint(15, 50)
            external_ratio     = random.uniform(0.6, 1.0)
            num_flows          = random.randint(50, 150)

        elif role == 'Access_01':
            # Auth brute-force: high packet rate, rapid short connections
            total_packets_out *= random.uniform(10, 30)
            num_flows          = random.randint(80, 200)
            avg_duration       = random.uniform(0.1, 0.5)

        elif role == 'Router_01':
            # DNS tunnelling / traffic redirection
            unique_dst_ips     = random.randint(50, 200)
            external_ratio     = random.uniform(0.8, 1.0)
            unique_dst_ports   = random.randint(1, 3)    # DNS only
            total_bytes_out   *= random.uniform(3, 8)

        avg_bytes_per_flow = total_bytes_out / max(num_flows, 1)

    return {
        "device_id":          role,
        "window_start":       datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
        "total_bytes_out":    round(total_bytes_out,    2),
        "total_packets_out":  total_packets_out,
        "avg_bytes_per_flow": round(avg_bytes_per_flow, 4),
        "num_flows":          num_flows,
        "unique_dst_ips":     unique_dst_ips,
        "unique_dst_ports":   unique_dst_ports,
        "unique_protocols":   unique_protocols,
        "external_ratio":     round(external_ratio,     4),
        "avg_duration":       avg_duration,
        "mode":               mode,
    }


# ── Startup banner ────────────────────────────────────────
print("=" * 56)
print(f"  IoT Trust-Drift Agent")
print(f"  Role   : {args.role}")
print(f"  Mode   : {args.mode.upper()}")
print(f"  Server : {SERVER}")
print("=" * 56)
print("Sending telemetry… (Ctrl-C to stop)\n")

INTERVAL = 8 if args.mode == 'normal' else 4  # malicious = faster

while True:
    data = collect(args.role, args.mode)
    try:
        resp = requests.post(
            f"{SERVER}/api/phone/telemetry",
            json=data,
            timeout=5,
        ).json()

        trust   = resp.get('trust_score', '?')
        risk    = resp.get('risk_level',  '?')
        anomaly = '⚠ ANOMALY' if resp.get('anomaly') else '✓ clean'
        drift   = resp.get('drift', 'NONE')
        policy  = resp.get('policy', '?')

        flag = '🔴' if args.mode == 'malicious' else '🟢'
        print(
            f"[{data['window_start']}] {flag} "
            f"trust={trust:<5} risk={risk:<8} {anomaly}  "
            f"drift={drift}  policy={policy}"
        )
    except Exception as e:
        print(f"[ERR] Could not reach server: {e}")

    time.sleep(INTERVAL)

