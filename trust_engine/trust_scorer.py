"""
Trust Engine — Trust Scorer + EMA Smoothing + Severity Mapping
  - Merges anomaly scores + drift results + policy results
  - Computes trust score (0-100) per device per window
  - Applies EMA smoothing (alpha=0.3) for stable scores
  - Maps severity: Low / Medium / High / Critical
"""

import pandas as pd
import numpy as np
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")


def map_severity(score: float) -> str:
    """Map trust score to severity level."""
    if score >= 81:
        return "Low"
    elif score >= 61:
        return "Medium"
    elif score >= 31:
        return "High"
    else:
        return "Critical"


def compute_trust_scores(anomaly_df, drift_df, policy_df) -> pd.DataFrame:
    """Compute trust scores by merging anomaly, drift, and policy data."""
    # Step 1: Merge all three DataFrames
    # Only keep needed columns to avoid duplicates (device_type, penalty, etc.)
    drift_cols = ["device_id", "window", "drift_magnitude", "drift_class"]
    drift_merge = drift_df[[c for c in drift_cols if c in drift_df.columns]] if len(drift_df) > 0 else drift_df

    policy_cols = ["device_id", "window", "policy_status", "violations"]
    policy_merge = policy_df[[c for c in policy_cols if c in policy_df.columns]] if len(policy_df) > 0 else policy_df

    merged = anomaly_df.merge(drift_merge, on=["device_id", "window"], how="left")
    merged = merged.merge(policy_merge, on=["device_id", "window"], how="left")

    # Step 2: Fill missing values
    merged["drift_class"] = merged["drift_class"].fillna("DRIFT_NONE")
    merged["policy_status"] = merged["policy_status"].fillna("COMPLIANT")
    merged["violations"] = merged["violations"].fillna("none")
    merged["drift_magnitude"] = merged["drift_magnitude"].fillna(0.0)

    # Step 3: Apply scoring formula
    def calculate_score(row):
        score = 100

        # Anomaly deduction (max -40)
        anomaly_deduction = row["anomaly_score"] * 40

        # Drift deduction
        if row["drift_class"] == "DRIFT_STRONG":
            drift_deduction = 20
        elif row["drift_class"] == "DRIFT_MILD":
            drift_deduction = 10
        else:
            drift_deduction = 0

        # Policy deduction
        if row["policy_status"] == "HARD_VIOLATION":
            policy_deduction = 40
        elif row["policy_status"] == "SOFT_DRIFT":
            policy_deduction = 15
        else:
            policy_deduction = 0

        # Calculate trust score with clamping
        trust_score = max(0, min(100, score - anomaly_deduction - drift_deduction - policy_deduction))

        return pd.Series({
            "trust_score": trust_score,
            "anomaly_deduction": anomaly_deduction,
            "drift_deduction": drift_deduction,
            "policy_deduction": policy_deduction,
        })

    # Apply the calculation
    score_cols = merged.apply(calculate_score, axis=1)
    merged = pd.concat([merged, score_cols], axis=1)

    # Step 4: Add severity column
    merged["severity"] = merged["trust_score"].apply(map_severity)

    # Step 5: Return with specified columns
    return merged[[
        "device_id", "device_type", "window", "trust_score", "severity",
        "anomaly_deduction", "drift_deduction", "policy_deduction",
        "anomaly_score", "drift_class", "policy_status",
    ]]


def apply_ema_smoothing(trust_df, alpha=0.3) -> pd.DataFrame:
    """Apply EMA smoothing to trust scores per device."""
    result_parts = []

    for device_id in trust_df["device_id"].unique():
        group = trust_df[trust_df["device_id"] == device_id].sort_values("window").copy()

        smoothed = []
        prev_smoothed = None

        for idx, row in group.iterrows():
            if prev_smoothed is None:
                current_smoothed = row["trust_score"]
            else:
                current_smoothed = alpha * row["trust_score"] + (1 - alpha) * prev_smoothed

            smoothed.append(round(current_smoothed, 2))
            prev_smoothed = current_smoothed

        group["trust_score_smoothed"] = smoothed
        result_parts.append(group)

    result = pd.concat(result_parts, ignore_index=True)

    # Add severity_smoothed column
    result["severity_smoothed"] = result["trust_score_smoothed"].apply(map_severity)

    return result


def run_trust_engine() -> pd.DataFrame:
    """Main orchestrator for trust engine."""
    print("=" * 55)
    print("  Trust Engine - Trust Score Pipeline")
    print("=" * 55)

    # Load anomaly scores
    anomaly_path = os.path.join(DATA_DIR, "anomaly_scores.csv")
    print(f"\n[1/5] Loading anomaly scores from {anomaly_path}...")
    anomaly_df = pd.read_csv(anomaly_path)
    anomaly_df["window"] = pd.to_datetime(anomaly_df["window"])
    print(f"  Loaded {len(anomaly_df)} rows")

    # Load drift results (or create empty if missing)
    drift_path = os.path.join(DATA_DIR, "drift_results.csv")
    if os.path.exists(drift_path):
        print(f"\n[2/5] Loading drift results from {drift_path}...")
        drift_df = pd.read_csv(drift_path)
        drift_df["window"] = pd.to_datetime(drift_df["window"])
        print(f"  Loaded {len(drift_df)} rows")
    else:
        print(f"\n[2/5] drift_results.csv not found - using defaults (DRIFT_NONE)")
        drift_df = pd.DataFrame(columns=["device_id", "window", "drift_magnitude", "drift_class"])

    # Load policy results (or create empty if missing)
    policy_path = os.path.join(DATA_DIR, "policy_results.csv")
    if os.path.exists(policy_path):
        print(f"\n[3/5] Loading policy results from {policy_path}...")
        policy_df = pd.read_csv(policy_path)
        policy_df["window"] = pd.to_datetime(policy_df["window"])
        print(f"  Loaded {len(policy_df)} rows")
    else:
        print(f"\n[3/5] policy_results.csv not found - using defaults (COMPLIANT)")
        policy_df = pd.DataFrame(columns=["device_id", "window", "policy_status", "violations"])

    # Compute raw trust scores
    print("\n[4/5] Computing trust scores...")
    trust_df = compute_trust_scores(anomaly_df, drift_df, policy_df)

    # Apply EMA smoothing
    print("[5/5] Applying EMA smoothing (alpha=0.3)...")
    final_df = apply_ema_smoothing(trust_df)

    # Save to CSV
    output_path = os.path.join(DATA_DIR, "trust_scores.csv")
    final_df.to_csv(output_path, index=False)
    print(f"\n  Saved to: {output_path}")

    # Print summary table per device
    print("\n" + "=" * 55)
    print("  TRUST SCORE SUMMARY")
    print("=" * 55)

    for dev in sorted(final_df["device_id"].unique()):
        dev_data = final_df[final_df["device_id"] == dev]
        min_score = dev_data["trust_score_smoothed"].min()
        max_score = dev_data["trust_score_smoothed"].max()
        print(f"\n  {dev}:")
        print(f"    Smoothed trust: {min_score:.1f} - {max_score:.1f}")
        print(f"    Severity range: {map_severity(min_score)} - {map_severity(max_score)}")

    # Severity distribution
    print("\n  Severity Distribution (smoothed):")
    for severity in ["Critical", "High", "Medium", "Low"]:
        count = len(final_df[final_df["severity_smoothed"] == severity])
        bar = "#" * count
        print(f"    {severity:>8}: {count:>3}  {bar}")

    print("\n" + "=" * 55)
    return final_df


if __name__ == "__main__":
    run_trust_engine()
    print("\nTrust Engine complete. Scores saved to data/trust_scores.csv")
