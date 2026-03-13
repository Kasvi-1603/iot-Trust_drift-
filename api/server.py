"""
FastAPI Backend — Serves CSV pipeline data as JSON.
All data is real, read directly from pipeline output CSVs.
"""

import os
import sys
import pandas as pd
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
