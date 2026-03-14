"""
IoT Trust & Drift — Full Pipeline Runner
=========================================
Runs all 5 stages in order with a single command:
  python run_pipeline.py

Stages:
  1. Anomaly Detection   -> anomaly_scores.csv
  2. Drift Detection     -> drift_results.csv
  3. Policy Engine       -> policy_results.csv
  4. Trust Scorer        -> trust_scores.csv
  5. Evidence Generator  -> evidence_reports.csv
"""

import time
import os
import sys

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)


def run_pipeline():
    start = time.time()

    print("=" * 60)
    print("  IoT Trust & Drift - Full Pipeline")
    print("  " + "=" * 56)
    print()

    # ---- Stage 1: Anomaly Detection ----
    print("[STAGE 1/5] Anomaly Detection")
    print("-" * 60)
    from ml_engine.anomaly_detector import (
        load_features, split_baseline_and_full,
        compute_baseline, train_per_device_type, score_all_devices,
    )
    import pandas as pd

    DATA_DIR = os.path.join(PROJECT_ROOT, "data")

    features = load_features("feature_vectors.csv")
    baseline, full = split_baseline_and_full(features, baseline_hours=48)
    baseline_stats = compute_baseline(baseline)
    models = train_per_device_type(baseline)
    scored = score_all_devices(models, full)
    scored.to_csv(os.path.join(DATA_DIR, "anomaly_scores.csv"), index=False)

    anomalies = scored[scored["is_anomaly"] == 1]
    print(f"  -> {len(scored)} windows scored, {len(anomalies)} anomalies detected")
    print(f"  -> Saved: anomaly_scores.csv")
    print()

    # ---- Stage 2: Drift Detection ----
    print("[STAGE 2/5] Drift Detection")
    print("-" * 60)
    from ml_engine.drift_detector import compute_drift, DRIFT_NONE

    drift_results = []
    for _, row in full.iterrows():
        device_id = row["device_id"]
        window = str(row["window"])
        if device_id not in baseline_stats:
            continue
        result = compute_drift(device_id, window, row.to_dict(), baseline_stats[device_id])
        drift_results.append({
            "device_id": result.device_id,
            "window": result.window_start,
            "drift_magnitude": result.drift_magnitude,
            "drift_class": result.drift_class,
            "top_drifters": str(result.top_drifters),
            "penalty": result.penalty,
        })

    drift_df = pd.DataFrame(drift_results)
    drift_df.to_csv(os.path.join(DATA_DIR, "drift_results.csv"), index=False)

    drifting = drift_df[drift_df["drift_class"] != DRIFT_NONE]
    print(f"  -> {len(drift_df)} windows analyzed, {len(drifting)} drifting")
    print(f"  -> Saved: drift_results.csv")
    print()

    # ---- Stage 3: Policy Engine ----
    print("[STAGE 3/5] Policy Engine")
    print("-" * 60)
    from trust_engine.policy_engine import evaluate_policy, COMPLIANT

    raw_df = pd.read_csv(os.path.join(DATA_DIR, "full_dataset.csv"), parse_dates=["timestamp"])
    raw_df["window"] = raw_df["timestamp"].dt.floor("h")

    feat_df = pd.read_csv(os.path.join(DATA_DIR, "feature_vectors.csv"))
    if "window_start" in feat_df.columns:
        feat_df = feat_df.rename(columns={"window_start": "window"})
    feat_df["window"] = pd.to_datetime(feat_df["window"])

    if "device_type" not in feat_df.columns:
        def get_dtype(did):
            if "CCTV" in did: return "CCTV"
            elif "Router" in did: return "Router"
            elif "Access" in did: return "AccessController"
            return "Unknown"
        feat_df["device_type"] = feat_df["device_id"].apply(get_dtype)

    policy_results = []
    for _, feat_row in feat_df.iterrows():
        device_id = feat_row["device_id"]
        device_type = feat_row["device_type"]
        window = feat_row["window"]

        mask = (raw_df["device_id"] == device_id) & (raw_df["window"] == window)
        window_flows = raw_df[mask].to_dict("records")

        result = evaluate_policy(device_id, device_type, str(window), feat_row.to_dict(), window_flows)
        policy_results.append({
            "device_id": result.device_id,
            "device_type": result.device_type,
            "window": result.window_start,
            "policy_status": result.status,
            "violations": "; ".join(result.violations) if result.violations else "none",
            "penalty": result.penalty,
        })

    policy_df = pd.DataFrame(policy_results)
    policy_df.to_csv(os.path.join(DATA_DIR, "policy_results.csv"), index=False)

    violations = policy_df[policy_df["policy_status"] != COMPLIANT]
    print(f"  -> {len(policy_df)} windows checked, {len(violations)} violations")
    print(f"  -> Saved: policy_results.csv")
    print()

    # ---- Stage 4: Trust Scorer ----
    print("[STAGE 4/5] Trust Scorer")
    print("-" * 60)
    from trust_engine.trust_scorer import run_trust_engine
    trust_df = run_trust_engine()
    print()

    # ---- Stage 5: Evidence Generator ----
    print("[STAGE 5/5] Evidence Generator")
    print("-" * 60)
    from explainability.evidence_generator import generate_evidence_reports
    evidence_df = generate_evidence_reports()

    # ---- Final Summary ----
    elapsed = time.time() - start
    print()
    print("=" * 60)
    print("  PIPELINE COMPLETE")
    print("=" * 60)
    print(f"  Time:       {elapsed:.1f} seconds")
    print(f"  Devices:    {scored['device_id'].nunique()}")
    print(f"  Windows:    {len(scored)}")
    print(f"  Anomalies:  {len(anomalies)}")
    print(f"  Drifts:     {len(drifting)}")
    print(f"  Violations: {len(violations)}")

    flagged = evidence_df[evidence_df["severity_smoothed"].isin(["Critical", "High"])]
    print(f"  High/Crit:  {len(flagged)}")
    print()
    print("  Output files in data/:")
    print("    anomaly_scores.csv")
    print("    drift_results.csv")
    print("    policy_results.csv")
    print("    trust_scores.csv")
    print("    evidence_reports.csv")
    print("=" * 60)


if __name__ == "__main__":
    run_pipeline()
