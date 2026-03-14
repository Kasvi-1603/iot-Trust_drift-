"""
FastAPI Backend — Serves CSV pipeline data as JSON.
All data is real, read directly from pipeline output CSVs.
"""

import os
import sys
import shutil
import subprocess
import asyncio
import pandas as pd
from datetime import datetime, timedelta
from pydantic import BaseModel
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

# Add project root to sys.path so we can import config/
PROJECT_ROOT_FOR_IMPORT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT_FOR_IMPORT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT_FOR_IMPORT)

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app):
    """Startup: launch the WebSocket broadcast loop."""
    print("[Startup] FastAPI server starting...")
    asyncio.create_task(_broadcast_live_data_loop())
    print("[Startup] WebSocket broadcast loop started")
    print("[Startup] Server ready! Listening on http://0.0.0.0:8002")
    yield

app = FastAPI(title="IoT Trust & Drift API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")

DEVICE_DESCRIPTIONS = {
    "CCTV": "IP Camera streaming to internal NVR",
    "Router": "DNS forwarder to Google DNS",
    "AccessController": "Badge reader authenticating to internal server",
}

# Global simulation state
SIMULATION_MODE = "normal"  # default: clean baseline only


def load_csv(filename):
    """Load CSV with optimized engine for speed."""
    path = os.path.join(DATA_DIR, filename)
    if not os.path.exists(path):
        return pd.DataFrame()
    return pd.read_csv(path, engine='c')  # C engine is faster


def _ensure_backup():
    """Back up the original CSVs so we can restore them (fast, only if needed)."""
    for fname in ["feature_vectors", "full_dataset"]:
        backup = os.path.join(DATA_DIR, f"{fname}_original.csv")
        source = os.path.join(DATA_DIR, f"{fname}.csv")
        if not os.path.exists(backup) and os.path.exists(source):
            shutil.copy2(source, backup)
            print(f"[Startup] Backed up {fname}.csv")


def _trim_to_baseline(skip_if_exists=True):
    """
    Trim full_dataset.csv and feature_vectors.csv to baseline-only
    (first 48 hours — no attack traffic) and re-run the pipeline.
    This ensures all devices start as green / Low severity.
    
    Args:
        skip_if_exists: If True, skip if baseline files already exist and look correct
    """
    # Check if we should skip (fast path)
    if skip_if_exists:
        trust_scores_path = os.path.join(DATA_DIR, "trust_scores.csv")
        if os.path.exists(trust_scores_path):
            # Quick check: if trust_scores exists and has data, assume baseline is ready
            try:
                trust_df = pd.read_csv(trust_scores_path, nrows=1)
                if not trust_df.empty:
                    print("[Startup] Baseline files exist, skipping pipeline re-run")
                    return
            except:
                pass  # If read fails, continue with setup
    
    # Trim full_dataset.csv
    full_backup = os.path.join(DATA_DIR, "full_dataset_original.csv")
    full_target = os.path.join(DATA_DIR, "full_dataset.csv")
    if os.path.exists(full_backup):
        raw = pd.read_csv(full_backup, parse_dates=["timestamp"], engine='c')
    elif os.path.exists(full_target):
        raw = pd.read_csv(full_target, parse_dates=["timestamp"], engine='c')
    else:
        return
    cutoff = raw["timestamp"].min() + pd.Timedelta(hours=48)
    raw_clean = raw[raw["timestamp"] < cutoff]
    raw_clean.to_csv(full_target, index=False)

    # Trim feature_vectors.csv
    feat_backup = os.path.join(DATA_DIR, "feature_vectors_original.csv")
    feat_target = os.path.join(DATA_DIR, "feature_vectors.csv")
    if os.path.exists(feat_backup):
        feat = pd.read_csv(feat_backup, engine='c')
    elif os.path.exists(feat_target):
        feat = pd.read_csv(feat_target, engine='c')
    else:
        return
    col = "window" if "window" in feat.columns else "window_start"
    feat[col] = pd.to_datetime(feat[col])
    feat_cutoff = feat[col].min() + pd.Timedelta(hours=48)
    feat_clean = feat[feat[col] < feat_cutoff]
    feat_clean.to_csv(feat_target, index=False)

    # Re-run pipeline with clean data (in background to not block startup)
    print("[Startup] Re-running pipeline in background...")
    subprocess.Popen(
        [sys.executable, "run_pipeline.py"],
        cwd=PROJECT_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


# Create backups on server start (fast, non-blocking)
print("[Startup] Initializing server...")
_ensure_backup()
# Start with clean baseline - skip if already exists (fast startup)
_trim_to_baseline(skip_if_exists=True)
print("[Startup] Initialization complete")


# ── Live Engine + Real Traffic Capture ────────────────
from simulators.live_engine import LiveEngine
from simulators.live_capture import LiveNetworkCapture

_live_engine = LiveEngine()
_live_capture = LiveNetworkCapture()

# Auto-start real traffic capture so data is available immediately
_live_capture.start()

# WebSocket connected clients
_ws_clients: set = set()


async def _broadcast_live_data_loop():
    """Background task: push real-time traffic data to all WebSocket clients every second.
    All blocking calls (lock-acquiring) are offloaded to thread pool so the event loop
    is never blocked, keeping all HTTP endpoints responsive.
    """
    loop = asyncio.get_event_loop()
    while True:
        if _ws_clients:
            try:
                # Offload ALL blocking/lock calls to thread pool — never block the event loop
                snapshot = await loop.run_in_executor(None, _live_capture.get_latest)
                scored = await loop.run_in_executor(None, lambda: _live_capture.get_scored_history(last_n=1))
                capture_status = await loop.run_in_executor(None, _live_capture.get_status)
                scoring = scored[-1] if scored else None

                if _live_engine.running:
                    sim_status = await loop.run_in_executor(None, _live_engine.get_live_stats)
                else:
                    sim_status = None

                payload = {
                    "type": "realtime",
                    "timestamp": datetime.now().isoformat(),
                    "real_traffic": snapshot,
                    "scoring": scoring,
                    "capture_status": capture_status,
                    "simulation": sim_status,
                }

                dead = set()
                for ws in list(_ws_clients):
                    try:
                        await ws.send_json(payload)
                    except Exception:
                        dead.add(ws)
                _ws_clients.difference_update(dead)
            except Exception as e:
                print(f"[Broadcast] Error: {e}")

        await asyncio.sleep(1)


# ── Simulation Control ──────────────────────────────────

@app.post("/api/simulate")
def simulate(mode: str = "normal"):
    """
    Toggle between normal and attack mode, re-run the full pipeline.
      mode="normal"  -> only first 48 hours (baseline, no attacks)
      mode="attack"  -> full dataset including CCTV attack hours
    """
    global SIMULATION_MODE
    SIMULATION_MODE = mode

    backup = os.path.join(DATA_DIR, "feature_vectors_original.csv")
    target = os.path.join(DATA_DIR, "feature_vectors.csv")

    # Always read from the original backup
    if os.path.exists(backup):
        feat_df = pd.read_csv(backup, engine='c')
    else:
        feat_df = pd.read_csv(target, engine='c')

    if "window_start" in feat_df.columns:
        feat_df = feat_df.rename(columns={"window_start": "window"})
    feat_df["window"] = pd.to_datetime(feat_df["window"])

    if mode == "normal":
        # Keep only first 48 hours (clean baseline — no attacks)
        cutoff = feat_df["window"].min() + pd.Timedelta(hours=48)
        filtered = feat_df[feat_df["window"] < cutoff]
    else:
        # Full dataset including attack hours 49-72
        filtered = feat_df

    # Overwrite feature_vectors.csv with the selected data
    filtered.to_csv(target, index=False)

    # Re-run the full pipeline
    result = subprocess.run(
        [sys.executable, "run_pipeline.py"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )

    return {
        "status": "done",
        "mode": mode,
        "windows": len(filtered),
        "message": f"Pipeline re-run in {mode} mode with {len(filtered)} windows",
    }


@app.get("/api/simulation-status")
def get_simulation_status():
    """Current simulation mode."""
    return {"mode": SIMULATION_MODE}


# ── Dashboard ──

@app.get("/api/stats")
def get_stats():
    """Summary statistics for dashboard header."""
    trust_df = load_csv("trust_scores.csv")
    evidence_df = load_csv("evidence_reports.csv")
    drift_df = load_csv("drift_results.csv")
    policy_df = load_csv("policy_results.csv")

    total_devices = trust_df["device_id"].nunique() if not trust_df.empty else 0
    total_windows = len(trust_df) if not trust_df.empty else 0

    # Latest trust per device
    if not trust_df.empty:
        trust_df["window"] = pd.to_datetime(trust_df["window"])
        latest = trust_df.sort_values("window").groupby("device_id").last().reset_index()
        avg_trust = round(latest["trust_score_smoothed"].mean(), 1)
        compromised = len(latest[latest["severity_smoothed"].isin(["High", "Critical"])])
    else:
        avg_trust = 0
        compromised = 0

    # Alerts count
    if not evidence_df.empty:
        alerts_count = len(evidence_df[evidence_df["severity_smoothed"] != "Low"])
        critical_count = len(evidence_df[evidence_df["severity_smoothed"] == "Critical"])
    else:
        alerts_count = 0
        critical_count = 0

    # Drift count
    if not drift_df.empty:
        drift_count = len(drift_df[drift_df["drift_class"] != "DRIFT_NONE"])
    else:
        drift_count = 0

    # Policy violations
    if not policy_df.empty:
        violation_count = len(policy_df[policy_df["policy_status"] != "COMPLIANT"])
    else:
        violation_count = 0

    return {
        "total_devices": total_devices,
        "total_windows": total_windows,
        "avg_trust": avg_trust,
        "compromised_devices": compromised,
        "healthy_devices": total_devices - compromised,
        "total_alerts": alerts_count,
        "critical_alerts": critical_count,
        "drift_events": drift_count,
        "policy_violations": violation_count,
    }


@app.get("/api/devices")
def get_devices():
    """List of devices with latest trust score + severity."""
    df = load_csv("trust_scores.csv")
    if df.empty:
        return []
    df["window"] = pd.to_datetime(df["window"])
    latest = df.sort_values("window").groupby("device_id").last().reset_index()
    results = []
    for _, row in latest.iterrows():
        results.append({
            "device_id": row["device_id"],
            "device_type": row["device_type"],
            "trust_score": round(row["trust_score_smoothed"], 1),
            "severity": row["severity_smoothed"],
            "description": DEVICE_DESCRIPTIONS.get(row["device_type"], ""),
            "anomaly_deduction": round(row.get("anomaly_deduction", 0), 1),
            "drift_deduction": round(row.get("drift_deduction", 0), 1),
            "policy_deduction": round(row.get("policy_deduction", 0), 1),
        })
    return results


@app.get("/api/trust-timeline")
def get_trust_timeline():
    """All trust scores over time for chart."""
    df = load_csv("trust_scores.csv")
    if df.empty:
        return []
    df["window"] = pd.to_datetime(df["window"])
    df = df.sort_values("window")
    results = []
    for _, row in df.iterrows():
        results.append({
            "window": row["window"].isoformat(),
            "device_id": row["device_id"],
            "trust_score": round(row["trust_score_smoothed"], 1),
            "severity": row["severity_smoothed"],
        })
    return results


@app.get("/api/alerts")
def get_alerts():
    """Flagged windows only (severity != Low)."""
    df = load_csv("evidence_reports.csv")
    if df.empty:
        return []
    df["window"] = pd.to_datetime(df["window"])
    flagged = df[df["severity_smoothed"] != "Low"].sort_values("window", ascending=False)
    results = []
    for _, row in flagged.iterrows():
        results.append({
            "window": row["window"].isoformat(),
            "device_id": row["device_id"],
            "device_type": row["device_type"],
            "severity": row["severity_smoothed"],
            "trust_score": round(row["trust_score_smoothed"], 1),
            "risk_summary": row["risk_summary"],
            "evidence": row["evidence"],
            "feature_attribution": row["feature_attribution"],
            "recommended_action": row["recommended_action"],
        })
    return results


@app.get("/api/all-evidence")
def get_all_evidence():
    """All evidence reports (all severities)."""
    df = load_csv("evidence_reports.csv")
    if df.empty:
        return []
    df["window"] = pd.to_datetime(df["window"])
    df = df.sort_values("window", ascending=False)
    results = []
    for _, row in df.iterrows():
        results.append({
            "window": row["window"].isoformat(),
            "device_id": row["device_id"],
            "device_type": row["device_type"],
            "severity": row["severity_smoothed"],
            "trust_score": round(row["trust_score_smoothed"], 1),
            "risk_summary": row["risk_summary"],
            "evidence": row["evidence"],
            "feature_attribution": row["feature_attribution"],
            "recommended_action": row["recommended_action"],
        })
    return results


# ── Device Detail ──

@app.get("/api/device/{device_id}")
def get_device_detail(device_id: str):
    """Full detail for one device."""
    evidence_df = load_csv("evidence_reports.csv")
    trust_df = load_csv("trust_scores.csv")

    if evidence_df.empty or trust_df.empty:
        return {"device_id": device_id, "timeline": [], "evidence": []}

    evidence_df["window"] = pd.to_datetime(evidence_df["window"])
    trust_df["window"] = pd.to_datetime(trust_df["window"])

    dev_trust = trust_df[trust_df["device_id"] == device_id].sort_values("window")
    dev_evidence = evidence_df[evidence_df["device_id"] == device_id].sort_values("window", ascending=False)

    if dev_trust.empty:
        return {"device_id": device_id, "timeline": [], "evidence": []}

    latest = dev_trust.iloc[-1]
    device_type = latest["device_type"]

    timeline = []
    for _, row in dev_trust.iterrows():
        timeline.append({
            "window": row["window"].isoformat(),
            "trust_score": round(row["trust_score_smoothed"], 1),
            "severity": row["severity_smoothed"],
            "anomaly_deduction": round(row.get("anomaly_deduction", 0), 1),
            "drift_deduction": round(row.get("drift_deduction", 0), 1),
            "policy_deduction": round(row.get("policy_deduction", 0), 1),
        })

    evidence = []
    for _, row in dev_evidence.iterrows():
        evidence.append({
            "window": row["window"].isoformat(),
            "trust_score": round(row["trust_score_smoothed"], 1),
            "severity": row["severity_smoothed"],
            "evidence": row["evidence"],
            "feature_attribution": row["feature_attribution"],
            "recommended_action": row["recommended_action"],
            "anomaly_score": round(row.get("anomaly_score", 0), 2),
            "drift_class": row.get("drift_class", "DRIFT_NONE"),
            "policy_status": row.get("policy_status", "COMPLIANT"),
        })

    return {
        "device_id": device_id,
        "device_type": device_type,
        "description": DEVICE_DESCRIPTIONS.get(device_type, ""),
        "current_trust": round(latest["trust_score_smoothed"], 1),
        "current_severity": latest["severity_smoothed"],
        "timeline": timeline,
        "evidence": evidence,
    }


# ── Analytics ──

@app.get("/api/anomaly-timeline")
def get_anomaly_timeline():
    """Anomaly scores over time per device."""
    df = load_csv("anomaly_scores.csv")
    if df.empty:
        return []
    df["window"] = pd.to_datetime(df["window"])
    df = df.sort_values("window")
    results = []
    for _, row in df.iterrows():
        results.append({
            "window": row["window"].isoformat(),
            "device_id": row["device_id"],
            "anomaly_score": round(row["anomaly_score"], 3),
            "is_anomaly": int(row["is_anomaly"]),
        })
    return results


@app.get("/api/drift-timeline")
def get_drift_timeline():
    """Drift magnitudes over time per device."""
    df = load_csv("drift_results.csv")
    if df.empty:
        return []
    df["window"] = pd.to_datetime(df["window"])
    df = df.sort_values("window")
    results = []
    for _, row in df.iterrows():
        results.append({
            "window": row["window"].isoformat(),
            "device_id": row["device_id"],
            "drift_magnitude": round(row["drift_magnitude"], 2),
            "drift_class": row["drift_class"],
        })
    return results


@app.get("/api/severity-distribution")
def get_severity_distribution():
    """Count of windows per severity level."""
    df = load_csv("trust_scores.csv")
    if df.empty:
        return []
    counts = df["severity_smoothed"].value_counts().to_dict()
    return [{"severity": k, "count": v} for k, v in counts.items()]


# ── Network ──

@app.get("/api/network-traffic")
def get_network_traffic():
    """Traffic volume (bytes + packets) per device per hour."""
    df = load_csv("feature_vectors.csv")
    if df.empty:
        return []
    if "window_start" in df.columns:
        df = df.rename(columns={"window_start": "window"})
    df["window"] = pd.to_datetime(df["window"])
    df = df.sort_values("window")
    results = []
    for _, row in df.iterrows():
        results.append({
            "window": row["window"].isoformat(),
            "device_id": row["device_id"],
            "total_bytes_out": round(row["total_bytes_out"], 0),
            "total_packets_out": round(row["total_packets_out"], 0),
            "num_flows": round(row["num_flows"], 0),
            "unique_dst_ips": round(row["unique_dst_ips"], 0),
            "unique_dst_ports": round(row["unique_dst_ports"], 0),
            "external_ratio": round(row["external_ratio"], 2),
        })
    return results


@app.get("/api/protocol-distribution")
def get_protocol_distribution():
    """Count of flows per protocol from raw dataset."""
    df = load_csv("full_dataset.csv")
    if df.empty:
        return []
    counts = df["protocol"].value_counts().to_dict()
    return [{"protocol": k, "count": v} for k, v in counts.items()]


@app.get("/api/port-distribution")
def get_port_distribution():
    """Count of flows per destination port."""
    df = load_csv("full_dataset.csv")
    if df.empty:
        return []
    counts = df["dst_port"].value_counts().head(10).to_dict()
    return [{"port": int(k), "count": v} for k, v in counts.items()]


@app.get("/api/top-destinations")
def get_top_destinations():
    """Top destination IPs by flow count."""
    df = load_csv("full_dataset.csv")
    if df.empty:
        return []
    counts = df["dst_ip"].value_counts().head(10).to_dict()
    results = []
    for ip, count in counts.items():
        is_internal = ip.startswith("192.168.") or ip.startswith("10.") or ip == "127.0.0.1"
        results.append({"dst_ip": ip, "count": count, "is_internal": is_internal})
    return results


# ── Security / Policy ──

@app.get("/api/policy-results")
def get_policy_results():
    """All policy evaluation results."""
    df = load_csv("policy_results.csv")
    if df.empty:
        return []
    df["window"] = pd.to_datetime(df["window"])
    df = df.sort_values("window", ascending=False)
    results = []
    for _, row in df.iterrows():
        results.append({
            "window": row["window"].isoformat(),
            "device_id": row["device_id"],
            "device_type": row["device_type"],
            "policy_status": row["policy_status"],
            "violations": row["violations"],
            "penalty": int(row["penalty"]),
        })
    return results


@app.get("/api/policy-summary")
def get_policy_summary():
    """Policy compliance summary per device."""
    df = load_csv("policy_results.csv")
    if df.empty:
        return []
    results = []
    for device_id in df["device_id"].unique():
        dev = df[df["device_id"] == device_id]
        total = len(dev)
        compliant = len(dev[dev["policy_status"] == "COMPLIANT"])
        soft = len(dev[dev["policy_status"] == "SOFT_DRIFT"])
        hard = len(dev[dev["policy_status"] == "HARD_VIOLATION"])
        results.append({
            "device_id": device_id,
            "device_type": dev.iloc[0]["device_type"],
            "total_windows": total,
            "compliant": compliant,
            "soft_drift": soft,
            "hard_violation": hard,
            "compliance_rate": round(compliant / total * 100, 1) if total > 0 else 0,
        })
    return results


@app.get("/api/attack-distribution")
def get_attack_distribution():
    """Attack type distribution from labeled data."""
    df = load_csv("full_dataset.csv")
    if df.empty:
        return []
    attacks = df[df["label"] != "normal"]
    if attacks.empty:
        return []
    counts = attacks["label"].value_counts().to_dict()
    return [{"attack_type": k, "count": v} for k, v in counts.items()]


# ── Device Profiling & Fingerprinting ──

@app.get("/api/device-profiles")
def get_device_profiles():
    """Device fingerprints / behavioral profiles — straight from config."""
    from config.device_profiles import DEVICE_PROFILES
    profiles = []
    for dtype, p in DEVICE_PROFILES.items():
        profiles.append({
            "device_type": dtype,
            "description": p["description"],
            "allowed_protocols": sorted(p["allowed_protocols"]),
            "allowed_ports": sorted(p["allowed_ports"]),
            "allowed_dst_ips": sorted(p["allowed_dst_ips"]),
            "allow_external": p["allow_external"],
            "bytes_range_min": p["bytes_range"][0],
            "bytes_range_max": p["bytes_range"][1],
            "bandwidth_max_bytes": p["bandwidth_max_bytes"],
            "max_unique_dst_ips": p["max_unique_dst_ips"],
            "max_unique_dst_ports": p["max_unique_dst_ports"],
            "expected_directions": sorted(p["expected_directions"]),
        })
    return profiles


@app.get("/api/device/{device_id}/assessment")
def get_device_assessment(device_id: str):
    """Latest 3-tier assessment breakdown for a single device."""
    trust_df = load_csv("trust_scores.csv")
    drift_df = load_csv("drift_results.csv")
    policy_df = load_csv("policy_results.csv")
    evidence_df = load_csv("evidence_reports.csv")

    if trust_df.empty:
        return {"device_id": device_id, "found": False}

    trust_df["window"] = pd.to_datetime(trust_df["window"])
    dev_trust = trust_df[trust_df["device_id"] == device_id].sort_values("window")

    if dev_trust.empty:
        return {"device_id": device_id, "found": False}

    latest = dev_trust.iloc[-1]

    # Drift detail for latest window
    drift_detail = {"drift_class": "DRIFT_NONE", "drift_magnitude": 0, "top_drifters": "", "penalty": 0}
    if not drift_df.empty:
        drift_df["window"] = pd.to_datetime(drift_df["window"])
        dev_drift = drift_df[(drift_df["device_id"] == device_id)]
        if not dev_drift.empty:
            d_latest = dev_drift.sort_values("window").iloc[-1]
            drift_detail = {
                "drift_class": d_latest["drift_class"],
                "drift_magnitude": round(float(d_latest["drift_magnitude"]), 2),
                "top_drifters": d_latest.get("top_drifters", ""),
                "penalty": int(d_latest["penalty"]),
            }

    # Policy detail for latest window
    policy_detail = {"policy_status": "COMPLIANT", "violations": "none", "penalty": 0}
    if not policy_df.empty:
        policy_df["window"] = pd.to_datetime(policy_df["window"])
        dev_policy = policy_df[(policy_df["device_id"] == device_id)]
        if not dev_policy.empty:
            p_latest = dev_policy.sort_values("window").iloc[-1]
            policy_detail = {
                "policy_status": p_latest["policy_status"],
                "violations": p_latest["violations"],
                "penalty": int(p_latest["penalty"]),
            }

    # Evidence for latest window
    evidence_detail = {"risk_summary": "", "evidence": "", "recommended_action": ""}
    if not evidence_df.empty:
        evidence_df["window"] = pd.to_datetime(evidence_df["window"])
        dev_ev = evidence_df[evidence_df["device_id"] == device_id]
        if not dev_ev.empty:
            e_latest = dev_ev.sort_values("window").iloc[-1]
            evidence_detail = {
                "risk_summary": e_latest.get("risk_summary", ""),
                "evidence": e_latest.get("evidence", ""),
                "feature_attribution": e_latest.get("feature_attribution", ""),
                "recommended_action": e_latest.get("recommended_action", ""),
            }

    return {
        "device_id": device_id,
        "found": True,
        "device_type": latest["device_type"],
        "description": DEVICE_DESCRIPTIONS.get(latest["device_type"], ""),
        "trust_score_smoothed": round(float(latest["trust_score_smoothed"]), 1),
        "trust_score_raw": round(float(latest["trust_score"]), 1),
        "severity": latest["severity_smoothed"],
        "anomaly_score": round(float(latest["anomaly_score"]), 3),
        "anomaly_deduction": round(float(latest["anomaly_deduction"]), 1),
        "drift": drift_detail,
        "policy": policy_detail,
        "evidence": evidence_detail,
    }


# ── Attack Injection System ──────────────────────────────
#    Generates realistic attack traffic, re-runs pipeline,
#    and produces live alerts.

# Import the attack injector
from simulators.attack_injector import (
    ATTACK_CATALOG,
    generate_attack_flows,
    extract_features,
    get_device_type,
)

# Track active injections in memory
_active_injections: dict = {}


class InjectRequest(BaseModel):
    device_id: str
    attack_type: str


@app.get("/api/attack-catalog")
def get_attack_catalog():
    """Return the full attack catalog grouped by device type."""
    return {
        dtype: [
            {"id": a["id"], "name": a["name"], "description": a["description"], "mitre": a["mitre"]}
            for a in attacks
        ]
        for dtype, attacks in ATTACK_CATALOG.items()
    }


@app.get("/api/injection-status")
def get_injection_status():
    """Return currently active injections."""
    return {"active_injections": _active_injections}


@app.post("/api/inject-attack")
def inject_attack(req: InjectRequest):
    """
    Inject an attack for a given device:
      1. Generate realistic attack flows
      2. Append to full_dataset.csv
      3. Re-extract features into feature_vectors.csv
      4. Re-run the full ML pipeline
      5. Return updated active_injections state
    """
    global _active_injections

    device_id = req.device_id
    attack_type = req.attack_type
    device_type = get_device_type(device_id)

    # Find attack metadata
    catalog_entry = None
    for a in ATTACK_CATALOG.get(device_type, []):
        if a["id"] == attack_type:
            catalog_entry = a
            break
    if catalog_entry is None:
        return {"error": f"Unknown attack: {device_type}/{attack_type}"}

    # Read the current full dataset
    full_ds_path = os.path.join(DATA_DIR, "full_dataset.csv")
    backup_full = os.path.join(DATA_DIR, "full_dataset_original.csv")

    # Back up original full_dataset if not yet done
    if not os.path.exists(backup_full) and os.path.exists(full_ds_path):
        shutil.copy2(full_ds_path, backup_full)

    raw_df = pd.read_csv(full_ds_path, parse_dates=["timestamp"], engine='c')

    # Determine attack start time: after the last timestamp in the dataset
    last_time = raw_df["timestamp"].max()
    attack_start = last_time + timedelta(hours=1)

    # Generate attack flows (2 hours of attack traffic)
    attack_flows = generate_attack_flows(device_id, attack_type, attack_start, duration_minutes=120)
    attack_df = pd.DataFrame(attack_flows)
    attack_df["timestamp"] = pd.to_datetime(attack_df["timestamp"])

    # Append attack flows to full_dataset.csv
    combined_raw = pd.concat([raw_df, attack_df], ignore_index=True)
    combined_raw.to_csv(full_ds_path, index=False)

    # Re-extract features from the combined dataset
    features = extract_features(combined_raw)
    feat_path = os.path.join(DATA_DIR, "feature_vectors.csv")

    # Backup original feature vectors
    feat_backup = os.path.join(DATA_DIR, "feature_vectors_original.csv")
    if not os.path.exists(feat_backup):
        orig_feat = pd.read_csv(feat_path, engine='c')
        orig_feat.to_csv(feat_backup, index=False)

    features.to_csv(feat_path, index=False)

    # Re-run the full pipeline
    result = subprocess.run(
        [sys.executable, "run_pipeline.py"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )

    # Record active injection
    _active_injections[device_id] = {
        "attack_type": attack_type,
        "attack_name": catalog_entry["name"],
        "mitre": catalog_entry["mitre"],
        "description": catalog_entry["description"],
        "injected_at": datetime.now().isoformat(),
        "attack_flows": len(attack_flows),
    }

    return {
        "status": "injected",
        "device_id": device_id,
        "attack_type": attack_type,
        "attack_name": catalog_entry["name"],
        "flows_injected": len(attack_flows),
        "pipeline_stdout": result.stdout[-500:] if result.stdout else "",
        "active_injections": _active_injections,
    }


@app.post("/api/reset")
def reset_to_baseline():
    """
    Reset everything to clean baseline (first 48 hours only):
      1. Restore full_dataset.csv from backup
      2. Restore feature_vectors.csv from backup
      3. Trim both to first 48 hours
      4. Re-run the pipeline (blocking — waits for completion)
      5. Clear active injections
    All devices will return to green / Low severity.
    """
    global _active_injections

    full_ds_path   = os.path.join(DATA_DIR, "full_dataset.csv")
    feat_path      = os.path.join(DATA_DIR, "feature_vectors.csv")
    backup_full    = os.path.join(DATA_DIR, "full_dataset_original.csv")
    backup_feat    = os.path.join(DATA_DIR, "feature_vectors_original.csv")

    # ── Step 1: Restore full_dataset from backup and trim to 48 h ──
    src_full = backup_full if os.path.exists(backup_full) else full_ds_path
    raw = pd.read_csv(src_full, parse_dates=["timestamp"], engine='c')
    cutoff = raw["timestamp"].min() + pd.Timedelta(hours=48)
    raw[raw["timestamp"] < cutoff].to_csv(full_ds_path, index=False)

    # ── Step 2: Restore feature_vectors from backup and trim to 48 h ──
    src_feat = backup_feat if os.path.exists(backup_feat) else feat_path
    feat = pd.read_csv(src_feat, engine='c')
    col = "window" if "window" in feat.columns else "window_start"
    feat[col] = pd.to_datetime(feat[col])
    feat_cutoff = feat[col].min() + pd.Timedelta(hours=48)
    feat[feat[col] < feat_cutoff].to_csv(feat_path, index=False)

    # ── Step 3: Re-run the full pipeline (blocking — must finish before returning) ──
    subprocess.run(
        [sys.executable, "run_pipeline.py"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )

    # ── Step 4: Clear active injections ──
    _active_injections = {}

    return {
        "status": "reset",
        "message": "System restored to clean baseline — all devices green",
        "active_injections": {},
    }


@app.post("/api/reset-device/{device_id}")
def reset_device(device_id: str):
    """
    Remove injected attack data for a single device and re-run the pipeline.
      1. Remove rows for this device that are beyond the 48-hour baseline window
         (cutoff is read from the original backup to get the true baseline start)
      2. Re-extract features
      3. Re-run the full ML pipeline (blocking)
      4. Clear this device from active injections
    """
    global _active_injections

    full_ds_path = os.path.join(DATA_DIR, "full_dataset.csv")
    feat_path    = os.path.join(DATA_DIR, "feature_vectors.csv")
    backup_full  = os.path.join(DATA_DIR, "full_dataset_original.csv")
    backup_feat  = os.path.join(DATA_DIR, "feature_vectors_original.csv")

    # --- Determine the 48-h cutoff from the ORIGINAL backup (not the modified file) ---
    ref_path = backup_full if os.path.exists(backup_full) else full_ds_path
    ref_df   = pd.read_csv(ref_path, parse_dates=["timestamp"], engine='c')
    cutoff   = ref_df["timestamp"].min() + pd.Timedelta(hours=48)

    # --- Clean full_dataset.csv: drop attack rows for this device past cutoff ---
    raw_df  = pd.read_csv(full_ds_path, parse_dates=["timestamp"], engine='c')
    cleaned = raw_df[~((raw_df["device_id"] == device_id) & (raw_df["timestamp"] >= cutoff))]
    cleaned.to_csv(full_ds_path, index=False)

    # --- Re-extract features from the original backup (or cleaned dataset) ---
    # Re-use feature backup if available (faster and more accurate baseline)
    if os.path.exists(backup_feat):
        feat_orig = pd.read_csv(backup_feat, engine='c')
        col = "window" if "window" in feat_orig.columns else "window_start"
        feat_orig[col] = pd.to_datetime(feat_orig[col])
        feat_cutoff = feat_orig[col].min() + pd.Timedelta(hours=48)
        # Keep all feature rows not belonging to this device past cutoff
        feat_clean = feat_orig[~((feat_orig["device_id"] == device_id) & (feat_orig[col] >= feat_cutoff))]
        feat_clean.to_csv(feat_path, index=False)
    else:
        from simulators.attack_injector import extract_features
        features = extract_features(cleaned)
        features.to_csv(feat_path, index=False)

    # --- Re-run the full pipeline (blocking) ---
    subprocess.run(
        [sys.executable, "run_pipeline.py"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )

    # Remove from active injections
    _active_injections.pop(device_id, None)

    return {
        "status": "reset",
        "device_id": device_id,
        "message": f"Attack removed for {device_id} — device restored to baseline",
        "active_injections": _active_injections,
    }


# ══════════════════════════════════════════════════════════
#  LIVE MODE — Real-Time Traffic Capture + Simulation
# ══════════════════════════════════════════════════════════


class LiveInjectRequest(BaseModel):
    device_id: str
    attack_type: str


# ── WebSocket endpoint (1-second push) ──

@app.websocket("/ws/live")
async def ws_live(websocket: WebSocket):
    """WebSocket for real-time traffic streaming (1 push/sec)."""
    await websocket.accept()
    _ws_clients.add(websocket)
    print(f"[WS] Client connected. Total clients: {len(_ws_clients)}")
    try:
        # Keep connection alive - wait for disconnect
        # The broadcast loop (_broadcast_live_data_loop) sends data to all clients
        while True:
            # Wait for any message or disconnect
            try:
                await websocket.receive_text()
            except:
                break
    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"[WS] Error: {e}")
    finally:
        _ws_clients.discard(websocket)
        print(f"[WS] Client disconnected. Total clients: {len(_ws_clients)}")


# ── Real Traffic Capture endpoints ──

@app.get("/api/live/capture/status")
def live_capture_status():
    """Status of real-time network capture."""
    return _live_capture.get_status()


@app.post("/api/live/capture/start")
def live_capture_start():
    """Start real-time network capture."""
    _live_capture.start()
    return {"status": "started", "interface": _live_capture.interface_name}


@app.post("/api/live/capture/stop")
def live_capture_stop():
    """Stop real-time network capture."""
    _live_capture.stop()
    return {"status": "stopped"}


@app.post("/api/live/capture/reset")
def live_capture_reset():
    """Reset capture — clear data, re-learn baseline."""
    _live_capture.reset()
    _live_capture.start()
    return {"status": "reset"}


@app.get("/api/live/capture/snapshots")
def live_capture_snapshots(last_n: int = 60):
    """Get recent traffic snapshots."""
    return _live_capture.get_snapshots(last_n=last_n)


@app.get("/api/live/capture/scored")
def live_capture_scored(last_n: int = 100):
    """Get scored traffic history."""
    return _live_capture.get_scored_history(last_n=last_n)


@app.get("/api/live/capture/alerts")
def live_capture_alerts(last_n: int = 50):
    """Get real-traffic alerts."""
    return _live_capture.get_alerts(last_n=last_n)


# ── Simulation Live Mode endpoints ──

@app.get("/api/live/status")
def live_status():
    """Status of both real capture + simulated live engine."""
    cap_status = _live_capture.get_status()
    sim_status = _live_engine.get_live_stats()
    return {**sim_status, "capture": cap_status}


@app.get("/api/live/timeline")
def live_timeline(last_n: int = 100):
    """Get simulated device timeline."""
    return _live_engine.get_timeline(last_n=last_n)


@app.get("/api/live/anomalies")
def live_anomalies(last_n: int = 50):
    """Get anomalous windows from simulation."""
    return _live_engine.get_anomaly_feed(last_n=last_n)


@app.get("/api/live/unknown-ips")
def live_unknown_ips(last_n: int = 50):
    """Get unknown IPs from simulation."""
    return _live_engine.get_unknown_ips(last_n=last_n)


@app.get("/api/live/violations")
def live_violations(last_n: int = 50):
    """Get policy violations from simulation."""
    return _live_engine.get_violations(last_n=last_n)


@app.post("/api/live/start")
def live_start(interval: int = 10):
    """Start simulated live data generation."""
    _live_engine.start(tick_interval=interval)
    return {"status": "started", "interval": interval}


@app.post("/api/live/stop")
def live_stop():
    """Stop simulated live data generation."""
    _live_engine.stop()
    return {"status": "stopped"}


@app.post("/api/live/reset")
def live_reset():
    """Reset simulated live data."""
    _live_engine.reset()
    return {"status": "reset"}


@app.post("/api/live/inject")
def live_inject(req: LiveInjectRequest):
    """Inject attack in live simulation mode."""
    result = _live_engine.inject_attack(req.device_id, req.attack_type)
    return result


@app.post("/api/live/clear-attack")
def live_clear_attack(device_id: str):
    """Clear attack from a device in live mode."""
    _live_engine.clear_attack(device_id)
    return {"status": "cleared", "device_id": device_id}


# ══════════════════════════════════════════════════════════════
#  PHONE AGENT INTEGRATION  — /api/phone/*
#  Phones run agent.py (Termux) and POST telemetry here every 8s.
#  We score it inline using the same LiveEngine ML pipeline.
# ══════════════════════════════════════════════════════════════

import socket as _socket
import threading as _threading
import collections

class PhoneTelemetry(BaseModel):
    device_id: str
    window_start: str
    total_bytes_out: float
    total_packets_out: float
    avg_bytes_per_flow: float
    num_flows: float
    unique_dst_ips: float
    unique_dst_ports: float
    unique_protocols: float
    external_ratio: float
    avg_duration: float
    mode: str = "normal"          # "normal" | "malicious"

DEVICE_TYPE_MAP = {
    "CCTV_01":   "CCTV",
    "Router_01": "Router",
    "Access_01": "AccessController",
}

# Rolling store (thread-safe)
_phone_lock    = _threading.Lock()
_phone_history = collections.deque(maxlen=500)   # last 500 readings
_phone_agents  = {}                               # device_id → latest scored record

def _get_local_ip() -> str:
    """Get the WiFi/LAN IP address of this laptop."""
    try:
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


@app.get("/api/phone/connection-info")
def phone_connection_info():
    """Returns the laptop's LAN IP so phones know where to connect."""
    ip = _get_local_ip()
    return {
        "server_url": f"http://{ip}:8002",
        "laptop_ip":  ip,
        "port":        8002,
        "endpoint":   "/api/phone/telemetry",
        "hint":       f"Run on phone:  python agent.py --role CCTV_01 --server http://{ip}:8002",
    }


@app.post("/api/phone/telemetry")
def phone_telemetry(payload: PhoneTelemetry):
    """
    Receive a telemetry window from a phone agent.
    Score it with Isolation Forest + Drift + Policy + Trust.
    Return trust_score and risk_level to the phone agent immediately.
    """
    device_type = DEVICE_TYPE_MAP.get(payload.device_id, "CCTV")

    features = {
        "total_bytes_out":    payload.total_bytes_out,
        "total_packets_out":  payload.total_packets_out,
        "avg_bytes_per_flow": payload.avg_bytes_per_flow,
        "num_flows":          payload.num_flows,
        "unique_dst_ips":     payload.unique_dst_ips,
        "unique_dst_ports":   payload.unique_dst_ports,
        "unique_protocols":   payload.unique_protocols,
        "external_ratio":     payload.external_ratio,
        "avg_duration":       payload.avg_duration,
    }

    # Score inline — reuse LiveEngine ML pipeline
    # Pass empty raw_flows; bandwidth + anomaly + drift checks still fire.
    scored = _live_engine._score_single_window(
        device_id=payload.device_id,
        device_type=device_type,
        features=features,
        raw_flows=[],
        window_str=payload.window_start,
    )

    record = {
        **scored,
        "mode":            payload.mode,
        "received_at":     datetime.now().isoformat(),
        "source":          "phone_agent",
        # Mirror the raw feature fields for charts
        "external_ratio":  payload.external_ratio,
        "total_bytes_out": payload.total_bytes_out,
        "num_flows":       payload.num_flows,
        "unique_dst_ips":  payload.unique_dst_ips,
    }

    with _phone_lock:
        _phone_history.append(record)
        _phone_agents[payload.device_id] = record

    return {
        "status":      "ok",
        "device_id":   payload.device_id,
        "trust_score": round(scored["trust_score_smoothed"], 1),
        "risk_level":  scored["severity"],
        "anomaly":     scored["is_anomaly"],
        "drift":       scored["drift_class"],
        "policy":      scored["policy_status"],
        "mode":        payload.mode,
    }


@app.get("/api/phone/devices")
def phone_devices():
    """All phone agents that have sent at least one telemetry window."""
    with _phone_lock:
        return list(_phone_agents.values())


@app.get("/api/phone/history")
def phone_history(device_id: str = None, last_n: int = 100):
    """Recent phone telemetry history, optionally filtered by device_id."""
    with _phone_lock:
        data = list(_phone_history)
    if device_id:
        data = [d for d in data if d["device_id"] == device_id]
    return data[-last_n:]


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
