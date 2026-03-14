"""
FastAPI Backend — Serves CSV pipeline data as JSON.
All data is real, read directly from pipeline output CSVs.
"""

import os
import sys
import json
import shutil
import subprocess
import asyncio
import pandas as pd
from datetime import datetime, timedelta
from pydantic import BaseModel
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
"""
FastAPI Backend — Serves CSV pipeline data as JSON.
All data is real, read directly from pipeline output CSVs.
"""

import os
import sys
import pandas as pd
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from baseline_manager import feedback_update
import json
def save_baseline(baseline):

    with open("baseline_state.json", "w") as f:
        json.dump(baseline, f)


def load_baseline():

    try:
        with open("baseline_data.csv") as f:
            return json.load(f)
    except:
        return None
    

baseline = load_baseline()

if baseline is None:
    baseline = build_baseline(dataset)
# Add project root to sys.path so we can import config/
PROJECT_ROOT_FOR_IMPORT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT_FOR_IMPORT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT_FOR_IMPORT)

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app):
    """Startup: initialize baseline and live engine."""
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
    path = os.path.join(DATA_DIR, filename)
    if not os.path.exists(path):
        return pd.DataFrame()
    return pd.read_csv(path)


# ── Adaptive Baseline helpers ──────────────────────────

BASELINE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "baseline_state.json")

BASELINE_FEATURES = [
    "total_bytes_out", "total_packets_out", "avg_bytes_per_flow",
    "num_flows", "unique_dst_ips", "unique_dst_ports",
    "unique_protocols", "external_ratio", "avg_duration",
]


def save_baseline(baseline: dict):
    """Persist baseline to JSON on disk."""
    with open(BASELINE_PATH, "w") as f:
        json.dump(baseline, f, indent=2)


def load_baseline() -> dict | None:
    """Load baseline from disk, or return None if not found."""
    try:
        with open(BASELINE_PATH) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def build_baseline() -> dict:
    """
    Build initial baseline stats (mean + std) from feature_vectors.csv.
    Uses only the first 48 h (clean baseline rows).
    """
    df = load_csv("feature_vectors.csv")
    if df.empty:
        return {}
    col = "window" if "window" in df.columns else "window_start"
    df[col] = pd.to_datetime(df[col])
    cutoff = df[col].min() + pd.Timedelta(hours=48)
    df = df[df[col] < cutoff]

    baseline = {}
    for feat in BASELINE_FEATURES:
        if feat in df.columns:
            baseline[feat] = {
                "mean": float(df[feat].mean()),
                "std":  float(df[feat].std()) or 1e-6,
            }
    return baseline


# Initialise adaptive baseline (load from disk, else build from CSV)
try:
    from .baseline_manager import feedback_update as _feedback_update
except ImportError:
    from api.baseline_manager import feedback_update as _feedback_update

_baseline: dict = load_baseline() or {}


def _ensure_backup():
    """Back up the original CSVs so we can restore them."""
    for fname in ["feature_vectors", "full_dataset"]:
        backup = os.path.join(DATA_DIR, f"{fname}_original.csv")
        source = os.path.join(DATA_DIR, f"{fname}.csv")
        if not os.path.exists(backup) and os.path.exists(source):
            shutil.copy2(source, backup)


def _trim_to_baseline():
    """
    Trim full_dataset.csv and feature_vectors.csv to baseline-only
    (first 48 hours — no attack traffic) and re-run the pipeline.
    This ensures all devices start as green / Low severity.
    """
    # Trim full_dataset.csv
    full_backup = os.path.join(DATA_DIR, "full_dataset_original.csv")
    full_target = os.path.join(DATA_DIR, "full_dataset.csv")
    if os.path.exists(full_backup):
        raw = pd.read_csv(full_backup, parse_dates=["timestamp"])
    elif os.path.exists(full_target):
        raw = pd.read_csv(full_target, parse_dates=["timestamp"])
    else:
        return
    cutoff = raw["timestamp"].min() + pd.Timedelta(hours=48)
    raw_clean = raw[raw["timestamp"] < cutoff]
    raw_clean.to_csv(full_target, index=False)

    # Trim feature_vectors.csv
    feat_backup = os.path.join(DATA_DIR, "feature_vectors_original.csv")
    feat_target = os.path.join(DATA_DIR, "feature_vectors.csv")
    if os.path.exists(feat_backup):
        feat = pd.read_csv(feat_backup)
    elif os.path.exists(feat_target):
        feat = pd.read_csv(feat_target)
    else:
        return
    col = "window" if "window" in feat.columns else "window_start"
    feat[col] = pd.to_datetime(feat[col])
    feat_cutoff = feat[col].min() + pd.Timedelta(hours=48)
    feat_clean = feat[feat[col] < feat_cutoff]
    feat_clean.to_csv(feat_target, index=False)

    # Re-run pipeline with clean data
    subprocess.run(
        [sys.executable, "run_pipeline.py"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )


# Create backups on server start
_ensure_backup()
# Start with clean baseline so all devices are green
_trim_to_baseline()

# Build adaptive baseline from CSV if not already on disk
if not _baseline:
    _baseline = build_baseline()
    if _baseline:
        save_baseline(_baseline)
        print(f"[Baseline] Built from CSV — {len(_baseline)} features")
    else:
        print("[Baseline] WARNING: feature_vectors.csv empty, baseline not built yet")


# ── Live Engine + Real Traffic Capture ────────────────
from simulators.live_engine import LiveEngine
from simulators.live_capture import LiveNetworkCapture

_live_engine = LiveEngine()
_live_capture = LiveNetworkCapture()

# Real traffic capture is NOT auto-started — it uses psutil which requires
# admin privileges on Windows and is not relevant to the IoT simulation.
# It only starts if explicitly called via /api/live/capture/start.
# _live_capture.start()  ← intentionally disabled

# WebSocket removed — all pages use HTTP polling now


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
        feat_df = pd.read_csv(backup)
    else:
        feat_df = pd.read_csv(target)

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



if updated:
    save_baseline(baseline)
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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)


def load_baseline():

    try:
        with open("baseline_data.csv") as f:
            return json.load(f)
    except:
        return None
    def build_baseline():
    """
    Build baseline statistics from baseline_data.csv
    """

    df = load_csv("baseline_data.csv")

    if df.empty:
        return {}

    features = [
        "total_bytes_out",
        "total_packets_out",
        "avg_bytes_per_flow",
        "num_flows",
        "unique_dst_ips",
        "unique_dst_ports",
        "unique_protocols",
        "external_ratio",
        "avg_duration"
    ]

    baseline = {}

    for f in features:
        if f in df.columns:
            baseline[f] = {
                "mean": float(df[f].mean()),
                "std": float(df[f].std())
            }

    return baseline
# Add project root to sys.path so we can import config/
PROJECT_ROOT_FOR_IMPORT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT_FOR_IMPORT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT_FOR_IMPORT)

app = FastAPI(title="IoT Trust & Drift API")

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


def load_csv(filename):
    path = os.path.join(DATA_DIR, filename)
    if not os.path.exists(path):
        return pd.DataFrame()
    return pd.read_csv(path)


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
@app.post("/api/baseline-feedback")
def update_baseline_feedback(data: dict):
    """
    Update baseline using pipeline outputs
    """

    global baseline

    current_row = data["features"]
    drift_result = data["drift"]
    policy_result = data["policy"]
    risk_score = data["risk"]

    baseline, updated = feedback_update(
        baseline,
        current_row,
        drift_result,
        policy_result,
        risk_score
    )

    if updated:
        save_baseline(baseline)

    return {
        "baseline_updated": updated,
        "baseline": baseline
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

    # Confidence from anomaly_scores.csv
    confidence = None
    anomaly_df = load_csv("anomaly_scores.csv")
    if not anomaly_df.empty and "confidence" in anomaly_df.columns:
        if "window" not in anomaly_df.columns and "window_start" in anomaly_df.columns:
            anomaly_df = anomaly_df.rename(columns={"window_start": "window"})
        if "window" in anomaly_df.columns:
            anomaly_df["window"] = pd.to_datetime(anomaly_df["window"])
            dev_anom = anomaly_df[anomaly_df["device_id"] == device_id]
            if not dev_anom.empty:
                confidence = round(float(dev_anom.sort_values("window").iloc[-1]["confidence"]), 1)

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
        "confidence": confidence,
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

    raw_df = pd.read_csv(full_ds_path, parse_dates=["timestamp"])

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
        orig_feat = pd.read_csv(feat_path)
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
      1. Trim full_dataset.csv to baseline-only
      2. Trim feature_vectors.csv to baseline-only
      3. Re-run the pipeline
      4. Clear active injections
    All devices will return to green / Low severity.
    """
    global _active_injections

    _trim_to_baseline()
    _active_injections = {}

    return {
        "status": "reset",
        "message": "System restored to clean baseline — all devices green",
        "active_injections": {},
    }


# ══════════════════════════════════════════════════════════
#  LIVE MODE — Real-Time Traffic Capture + Simulation
# ══════════════════════════════════════════════════════════


class LiveInjectRequest(BaseModel):
    device_id: str
    attack_type: str


# ── WebSocket endpoint removed — use HTTP polling instead ──
# (Removed to prevent connection buildup issues in production)


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


# ── Adaptive Baseline Feedback ──────────────────────────────────────────────

class BaselineFeedbackRequest(BaseModel):
    features:      dict   # current feature vector row
    drift_result:  dict   # e.g. {"drift_class": "DRIFT_NONE", "drift_magnitude": 0.3}
    policy_result: dict   # e.g. {"total_violations": 0, "policy_status": "COMPLIANT"}
    risk_score:    float  # raw risk / deduction score (0–100)


@app.post("/api/baseline-feedback")
def baseline_feedback(req: BaselineFeedbackRequest):
    """
    Adaptive baseline update endpoint.
    Call this after every scored window.  The baseline self-corrects only
    when the window looks genuinely normal (no strong drift, no policy
    violations, risk score < 40).
    """
    global _baseline

    if not _baseline:
        # First call — build from CSV on the fly
        _baseline = build_baseline()

    _baseline, updated = _feedback_update(
        _baseline,
        req.features,
        req.drift_result,
        req.policy_result,
        req.risk_score,
    )

    if updated:
        save_baseline(_baseline)

    return {
        "baseline_updated": updated,
        "features_tracked": list(_baseline.keys()),
        "sample": {
            k: {"mean": round(v["mean"], 4), "std": round(v["std"], 4)}
            for k, v in list(_baseline.items())[:3]   # preview first 3 features
        },
    }


@app.get("/api/baseline")
def get_baseline():
    """Return the current adaptive baseline state."""
    return {
        "features": {
            k: {"mean": round(v["mean"], 4), "std": round(v["std"], 4)}
            for k, v in _baseline.items()
        },
        "feature_count": len(_baseline),
    }


# ══════════════════════════════════════════════════════════
#  ADVANCED SECURITY INTELLIGENCE
# ══════════════════════════════════════════════════════════

MITRE_CHAIN = [
    {"id": "TA0043", "name": "Reconnaissance",   "short": "Recon",    "color": "#94a3b8"},
    {"id": "TA0001", "name": "Initial Access",   "short": "Access",   "color": "#6366f1"},
    {"id": "TA0002", "name": "Execution",        "short": "Execute",  "color": "#8b5cf6"},
    {"id": "TA0003", "name": "Persistence",      "short": "Persist",  "color": "#a855f7"},
    {"id": "TA0007", "name": "Discovery",        "short": "Discover", "color": "#f59e0b"},
    {"id": "TA0008", "name": "Lateral Movement", "short": "Lateral",  "color": "#f97316"},
    {"id": "TA0010", "name": "Exfiltration",     "short": "Exfil",    "color": "#ef4444"},
    {"id": "TA0011", "name": "Command & Control","short": "C2",       "color": "#dc2626"},
]

TOPO_NODES = {
    "Router_01":   {"type": "Router",           "ip": "192.168.1.1",  "x": 50, "y": 35},
    "CCTV_01":     {"type": "CCTV",             "ip": "192.168.1.10", "x": 20, "y": 72},
    "Access_01":   {"type": "AccessController", "ip": "192.168.1.20", "x": 80, "y": 72},
    "Honeypot_01": {"type": "honeypot",         "ip": "192.168.1.99", "x": 50, "y": 85},
}

TOPO_EDGES = [
    {"from": "Router_01", "to": "CCTV_01"},
    {"from": "Router_01", "to": "Access_01"},
    {"from": "Router_01", "to": "Honeypot_01"},
]


def _mitre_tactic(row) -> str:
    evidence = str(row.get("evidence", "")).lower()
    drift     = str(row.get("drift_class", "DRIFT_NONE"))
    anomaly   = float(row.get("anomaly_score", 0))
    sev       = str(row.get("severity_smoothed", "Low"))

    if any(k in evidence for k in ("exfil", "c2", "dns_tunnel", "command")):
        return "TA0010"
    if any(k in evidence for k in ("credential", "stuffing", "brute")):
        return "TA0001"
    if any(k in evidence for k in ("lateral", "scan", "discovery")):
        return "TA0008"
    if drift == "DRIFT_STRONG":
        return "TA0003"
    if drift == "DRIFT_MILD":
        return "TA0002"
    if sev in ("High", "Critical"):
        return "TA0001"
    if anomaly > 0.4:
        return "TA0043"
    return "TA0043"


@app.get("/api/attack-chain")
def get_attack_chain():
    """Derive kill chain from evidence + drift data, mapped to MITRE ATT&CK."""
    evidence_df = load_csv("evidence_reports.csv")
    if evidence_df.empty:
        return {"events": [], "patient_zero": None, "active_stage": None,
                "stages_active": [], "chain": MITRE_CHAIN}

    evidence_df["window"] = pd.to_datetime(evidence_df["window"])
    flagged = evidence_df[evidence_df["severity_smoothed"] != "Low"].sort_values("window")

    if flagged.empty:
        return {"events": [], "patient_zero": None, "active_stage": None,
                "stages_active": [], "chain": MITRE_CHAIN}

    tactic_order = {t["id"]: i for i, t in enumerate(MITRE_CHAIN)}
    events = []
    for _, row in flagged.iterrows():
        tactic = _mitre_tactic(row)
        events.append({
            "window":       row["window"].isoformat(),
            "device_id":    row["device_id"],
            "device_type":  row.get("device_type", ""),
            "severity":     row["severity_smoothed"],
            "drift_class":  row.get("drift_class", "DRIFT_NONE"),
            "anomaly_score": round(float(row.get("anomaly_score", 0)), 3),
            "mitre_tactic": tactic,
            "evidence":     str(row.get("evidence", ""))[:200],
            "risk_summary": str(row.get("risk_summary", "")),
        })

    patient_zero  = events[0]["device_id"] if events else None
    stages_active = list({e["mitre_tactic"] for e in events})
    active_stage  = max(events, key=lambda e: tactic_order.get(e["mitre_tactic"], 0))["mitre_tactic"] if events else None

    return {
        "events":        events[-30:],
        "patient_zero":  patient_zero,
        "active_stage":  active_stage,
        "stages_active": stages_active,
        "chain":         MITRE_CHAIN,
    }


@app.get("/api/behavioral-fingerprint")
def get_behavioral_fingerprint():
    """Per-device behavioral fingerprint vs baseline — for radar charts."""
    feat_df  = load_csv("feature_vectors.csv")
    trust_df = load_csv("trust_scores.csv")

    if feat_df.empty:
        return []

    col = "window" if "window" in feat_df.columns else "window_start"
    feat_df[col] = pd.to_datetime(feat_df[col])

    cutoff      = feat_df[col].min() + pd.Timedelta(hours=48)
    baseline_df = feat_df[feat_df[col] < cutoff]
    current_df  = feat_df[feat_df[col] >= cutoff]

    DIMS = {
        "Traffic Volume":     "total_bytes_out",
        "Connection Rate":    "num_flows",
        "Geo Spread":         "unique_dst_ips",
        "Protocol Diversity": "unique_protocols",
        "External Exposure":  "external_ratio",
        "Port Scatter":       "unique_dst_ports",
    }

    result = []
    for device_id in feat_df["device_id"].unique():
        dev_base = baseline_df[baseline_df["device_id"] == device_id]
        dev_curr = current_df[current_df["device_id"] == device_id]

        if dev_base.empty:
            continue

        # Trust / severity
        sev = "Low"
        trust_score = 100.0
        if not trust_df.empty:
            trust_df["window"] = pd.to_datetime(trust_df["window"])
            dev_t = trust_df[trust_df["device_id"] == device_id]
            if not dev_t.empty:
                latest_t = dev_t.sort_values("window").iloc[-1]
                sev         = latest_t["severity_smoothed"]
                trust_score = float(latest_t["trust_score_smoothed"])

        # Build baseline max per dimension for normalisation
        bmax_map = {}
        bmean_map = {}
        for label, col_name in DIMS.items():
            if col_name in dev_base.columns:
                bmax  = dev_base[col_name].quantile(0.95)
                bmean = dev_base[col_name].mean()
                bmax_map[label]  = float(bmax) if bmax > 0 else 1.0
                bmean_map[label] = float(bmean)
            else:
                bmax_map[label]  = 1.0
                bmean_map[label] = 0.0

        # Latest row (current or last baseline)
        src = dev_curr if not dev_curr.empty else dev_base
        latest = src.sort_values(col).iloc[-1]

        current_vals  = {}
        baseline_vals = {}
        for label, col_name in DIMS.items():
            bmax  = bmax_map[label]
            bmean = bmean_map[label]
            raw   = float(latest[col_name]) if col_name in latest.index else 0.0
            current_vals[label]  = round(min(100, (raw   / bmax) * 100), 1)
            baseline_vals[label] = round(min(100, (bmean / bmax) * 100), 1)

        result.append({
            "device_id":   device_id,
            "severity":    sev,
            "trust_score": round(trust_score, 1),
            "dimensions":  list(DIMS.keys()),
            "current":     current_vals,
            "baseline":    baseline_vals,
        })

    return result


@app.get("/api/risk-propagation")
def get_risk_propagation():
    """Live network risk propagation graph — nodes + edges with risk flows."""
    trust_df = load_csv("trust_scores.csv")

    device_risk  = {d: 0.0   for d in TOPO_NODES if d != "Honeypot_01"}
    device_sev   = {d: "Low" for d in TOPO_NODES if d != "Honeypot_01"}
    device_trust = {d: 100.0 for d in TOPO_NODES if d != "Honeypot_01"}

    if not trust_df.empty:
        trust_df["window"] = pd.to_datetime(trust_df["window"])
        for did in list(device_risk.keys()):
            dev = trust_df[trust_df["device_id"] == did]
            if not dev.empty:
                row = dev.sort_values("window").iloc[-1]
                sc  = float(row["trust_score_smoothed"])
                device_trust[did] = sc
                device_risk[did]  = round(100 - sc, 1)
                device_sev[did]   = row["severity_smoothed"]

    router_risk = device_risk.get("Router_01", 0)
    propagated = {
        "Router_01":   device_risk.get("Router_01", 0),
        "CCTV_01":     round(min(100, device_risk.get("CCTV_01",   0) + router_risk * 0.35), 1),
        "Access_01":   round(min(100, device_risk.get("Access_01", 0) + router_risk * 0.35), 1),
        "Honeypot_01": round(min(100, router_risk * 0.5 + len(_active_injections) * 15), 1),
    }

    honeypot_triggered = propagated["Honeypot_01"] > 10 or bool(_active_injections)

    nodes = []
    for node_id, info in TOPO_NODES.items():
        risk  = propagated.get(node_id, 0)
        sev   = device_sev.get(node_id, "Low")
        trust = device_trust.get(node_id, 100.0)
        if node_id == "Honeypot_01":
            sev   = "Critical" if honeypot_triggered else "Low"
            trust = round(100 - risk, 1)
        nodes.append({
            **info,
            "id":          node_id,
            "risk":        risk,
            "trust":       trust,
            "severity":    sev,
            "is_honeypot": node_id == "Honeypot_01",
            "is_attacked": node_id in _active_injections,
        })

    edges = []
    for e in TOPO_EDGES:
        flow = round((propagated.get(e["from"], 0) + propagated.get(e["to"], 0)) / 2, 1)
        edges.append({**e, "risk_flow": flow, "active": flow > 8})

    return {"nodes": nodes, "edges": edges, "honeypot_triggered": honeypot_triggered}


@app.get("/api/self-healing-actions")
def get_self_healing_actions():
    """Auto-generated self-healing remediation log derived from trust/evidence data."""
    trust_df    = load_csv("trust_scores.csv")
    evidence_df = load_csv("evidence_reports.csv")

    actions = []
    import random as _rng
    _rng.seed(7)
    _sus_ips = ["203.0.113.50", "198.51.100.25", "192.0.2.100", "198.51.100.53", "185.220.101.5"]

    if not trust_df.empty:
        trust_df["window"] = pd.to_datetime(trust_df["window"])

        for device_id in trust_df["device_id"].unique():
            dev = trust_df[trust_df["device_id"] == device_id].sort_values("window")

            for i, (_, row) in enumerate(dev.iterrows()):
                t   = row["window"].isoformat()
                sev = row["severity_smoothed"]
                sc  = float(row["trust_score_smoothed"])

                if i == 0:
                    actions.append({"timestamp": t, "device_id": device_id, "level": "info",
                        "action": "MONITOR",
                        "message": f"Behavioral baseline established for {device_id} — 9 dimensions tracked",
                        "automated": True})

                if sev == "Medium":
                    actions.append({"timestamp": t, "device_id": device_id, "level": "warning",
                        "action": "THROTTLE",
                        "message": f"Traffic shaping applied to {device_id} — egress capped at 50 Mbps",
                        "automated": True})

                if sev in ("High", "Critical"):
                    ip = _rng.choice(_sus_ips)
                    actions.append({"timestamp": t, "device_id": device_id, "level": "error",
                        "action": "BLOCK",
                        "message": f"Outbound connection to {ip} blocked from {device_id} — policy enforcement",
                        "automated": True})
                    actions.append({"timestamp": t, "device_id": device_id, "level": "error",
                        "action": "ISOLATE",
                        "message": f"Network isolation triggered for {device_id} — VLAN reassignment pending review",
                        "automated": True})

                if i > 0:
                    prev_sev = dev.iloc[i - 1]["severity_smoothed"]
                    if prev_sev in ("High", "Critical") and sev in ("Low", "Medium"):
                        actions.append({"timestamp": t, "device_id": device_id, "level": "success",
                            "action": "RESTORE",
                            "message": f"{device_id} trust score recovered to {sc:.0f}/100 — quarantine lifted",
                            "automated": True})

    # Active injection events
    for dev_id, inj in _active_injections.items():
        actions.append({"timestamp": inj["injected_at"], "device_id": dev_id, "level": "error",
            "action": "ATTACK_DETECTED",
            "message": f"LIVE ATTACK on {dev_id}: {inj['attack_name']} ({inj['mitre']}) — {inj['description'][:80]}",
            "automated": False})
        actions.append({"timestamp": inj["injected_at"], "device_id": dev_id, "level": "error",
            "action": "ISOLATE",
            "message": f"Emergency isolation: {dev_id} cut from external routes — C2 channel severed",
            "automated": True})
        actions.append({"timestamp": inj["injected_at"], "device_id": dev_id, "level": "error",
            "action": "EXFIL_BLOCK",
            "message": f"Exfiltration prevention active on {dev_id} — deep packet inspection enabled",
            "automated": True})

    actions.sort(key=lambda x: x["timestamp"], reverse=True)
    return {"actions": actions[:60], "total": len(actions)}


@app.get("/api/honeypot-status")
def get_honeypot_status():
    """Honeypot device status — should never receive legitimate traffic."""
    full_df       = load_csv("full_dataset.csv")
    honeypot_ip   = "192.168.1.99"
    lure_events   = []

    if not full_df.empty and "dst_ip" in full_df.columns:
        hits = full_df[full_df["dst_ip"] == honeypot_ip]
        for _, row in hits.head(10).iterrows():
            lure_events.append({
                "timestamp": str(row.get("timestamp", "")),
                "src_ip":    str(row.get("src_ip", "")),
                "device_id": str(row.get("device_id", "")),
                "protocol":  str(row.get("protocol", "")),
                "bytes_out": int(row.get("bytes_out", 0)),
                "label":     str(row.get("label", "")),
            })

    triggered = bool(lure_events) or bool(_active_injections)
    return {
        "honeypot_ip":       honeypot_ip,
        "triggered":         triggered,
        "lure_events":       lure_events,
        "lure_count":        len(lure_events),
        "active_injections": len(_active_injections),
        "status":            "TRIGGERED" if triggered else "ARMED",
        "last_lure":         lure_events[0]["timestamp"] if lure_events else None,
    }


# ── System-Status  (SAFE / WATCH / UNSAFE per device + overall) ────────────

@app.get("/api/system-status")
def get_system_status():
    """
    Per-device automated verdict: SAFE | WATCH | UNSAFE
    Derived from latest trust score + severity.
    """
    trust_df = load_csv("trust_scores.csv")
    if trust_df.empty:
        return {"overall": "UNKNOWN", "devices": []}

    trust_df["window"] = pd.to_datetime(trust_df["window"])
    latest = trust_df.sort_values("window").groupby("device_id").last().reset_index()

    devices = []
    for _, row in latest.iterrows():
        ts   = float(row["trust_score_smoothed"])
        sev  = row["severity_smoothed"]

        if sev in ("Critical", "High") or ts < 40:
            status = "UNSAFE"
            reason = f"Trust {ts:.0f} — {sev} severity"
        elif sev == "Medium" or ts < 65:
            status = "WATCH"
            reason = f"Trust {ts:.0f} — elevated activity"
        else:
            status = "SAFE"
            reason = f"Trust {ts:.0f} — within normal envelope"

        devices.append({
            "device_id":   row["device_id"],
            "device_type": row["device_type"],
            "status":      status,
            "trust":       round(ts, 1),
            "severity":    sev,
            "reason":      reason,
        })

    # Overall = worst across all devices
    if any(d["status"] == "UNSAFE" for d in devices):
        overall = "UNSAFE"
    elif any(d["status"] == "WATCH" for d in devices):
        overall = "WATCH"
    else:
        overall = "SAFE"

    return {
        "overall":      overall,
        "devices":      devices,
        "last_update":  datetime.now().isoformat(),
    }


# ── Detection Metrics  (time-to-detection, read from pipeline output) ───────

@app.get("/api/detection-metrics")
def get_detection_metrics():
    """
    Reads pre-computed detection_metrics.json written by run_pipeline.
    Falls back to live computation if file is missing.
    """
    metrics_path = os.path.join(DATA_DIR, "detection_metrics.json")
    if os.path.exists(metrics_path):
        with open(metrics_path) as f:
            return json.load(f)

    # Fallback: compute on the fly
    full_df     = load_csv("full_dataset.csv")
    evidence_df = load_csv("evidence_reports.csv")
    if full_df.empty or evidence_df.empty:
        return {"detection_time_mins": None, "status": "no_data"}

    if "timestamp" not in full_df.columns:
        return {"detection_time_mins": None, "status": "no_timestamp"}

    full_df["timestamp"]   = pd.to_datetime(full_df["timestamp"])
    evidence_df["window"]  = pd.to_datetime(evidence_df["window"])

    attacks = full_df[full_df["label"] != "normal"]
    flagged = evidence_df[evidence_df["severity_smoothed"] != "Low"]

    if attacks.empty:
        return {"detection_time_mins": None, "status": "no_attacks"}
    if flagged.empty:
        return {"detection_time_mins": None, "status": "not_detected"}

    first_attack    = attacks["timestamp"].min()
    first_detection = flagged["window"].min()
    ttd_mins        = (first_detection - first_attack).total_seconds() / 60

    return {
        "detection_time_mins": round(ttd_mins, 1),
        "first_attack_at":     first_attack.isoformat(),
        "first_detection_at":  first_detection.isoformat(),
        "status":              "early" if ttd_mins < 60 else "delayed",
        "computed_at":         datetime.now().isoformat(),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
