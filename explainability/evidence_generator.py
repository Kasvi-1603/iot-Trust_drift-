"""
Explainability Engine - Evidence Generator
==========================================
Generates human-readable evidence for every device window.

For each window, produces:
  - risk_summary:       one-line verdict
  - evidence:           specific findings
  - feature_attribution: which features contributed most
  - recommended_action:  what an admin should do

Input:  trust_scores.csv, drift_results.csv, policy_results.csv, anomaly_scores.csv
Output: evidence_reports.csv
"""

import pandas as pd
import numpy as np
import ast
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")


def parse_top_drifters(top_drifters_str: str) -> list:
    """Parse top_drifters string into list of tuples."""
    if pd.isna(top_drifters_str) or top_drifters_str == "":
        return []

    try:
        return ast.literal_eval(top_drifters_str)
    except:
        return []


def build_evidence_text(row) -> dict:
    """Build evidence text for a single row."""
    evidence_parts = []
    active_signals = []

    # Anomaly evidence
    if row["anomaly_score"] > 0.5:
        evidence_parts.append(f"ML anomaly score {row['anomaly_score']:.2f} (-{row['anomaly_deduction']:.1f}pts).")
        active_signals.append("ML anomaly")

    # Drift evidence
    if row["drift_class"] == "DRIFT_STRONG":
        evidence_parts.append(f"STRONG behavioural drift -- magnitude {row['drift_magnitude']:.1f}.")

        # Parse and add top drifters
        top_drifters = parse_top_drifters(row.get("top_drifters", "[]"))
        if top_drifters:
            top_3 = top_drifters[:3]
            drifter_strs = [f"{feat} (z={val:.1f})" for feat, val in top_3]
            evidence_parts.append(f"Top drifted features: {', '.join(drifter_strs)}.")

        active_signals.append("strong drift")

    elif row["drift_class"] == "DRIFT_MILD":
        evidence_parts.append(f"MILD behavioural drift detected -- magnitude {row['drift_magnitude']:.1f}.")

    # Policy evidence
    if row["policy_status"] == "HARD_VIOLATION":
        evidence_parts.append(f"HARD policy violation: {row['violations']}.")
        active_signals.append("policy violation")
    elif row["policy_status"] == "SOFT_DRIFT":
        evidence_parts.append(f"SOFT policy drift: {row['violations']}.")

    # Build evidence field
    if evidence_parts:
        evidence = " ".join(evidence_parts)
    else:
        evidence = "All checks passed."

    # Build feature_attribution field
    attribution_parts = []
    if row["anomaly_deduction"] > 0:
        attribution_parts.append(f"anomaly_score={row['anomaly_score']:.2f} (-{row['anomaly_deduction']:.1f}pts)")
    if row["drift_deduction"] > 0:
        attribution_parts.append(f"drift={row['drift_class']} (-{row['drift_deduction']:.0f}pts)")
    if row["policy_deduction"] > 0:
        attribution_parts.append(f"policy={row['policy_status']} (-{row['policy_deduction']:.0f}pts)")

    feature_attribution = "; ".join(attribution_parts) if attribution_parts else "none"

    # Build risk_summary field
    severity = row["severity_smoothed"]
    device_id = row["device_id"]
    trust = row["trust_score_smoothed"]

    if severity == "Critical":
        signals_str = " + ".join(active_signals) if active_signals else "multiple factors"
        risk_summary = (
            f"CRITICAL: {device_id} trust={trust:.1f}. "
            f"Triggered by: {signals_str}. ISOLATE IMMEDIATELY."
        )
        recommended_action = "Isolate device and investigate immediately. Block network access if possible."

    elif severity == "High":
        signals_str = " + ".join(active_signals) if active_signals else "multiple factors"
        risk_summary = (
            f"HIGH RISK: {device_id} trust={trust:.1f}. "
            f"Triggered by: {signals_str}."
        )
        recommended_action = "Investigate device behaviour. Consider temporary network restriction."

    elif severity == "Medium":
        risk_summary = f"MEDIUM RISK: {device_id} trust={trust:.1f}. Monitor closely."
        recommended_action = "Monitor device closely over next 2-3 hours. No immediate action required."

    else:  # Low
        risk_summary = f"LOW RISK: {device_id} operating normally. Trust: {trust:.1f}."
        recommended_action = "No action needed. Device operating within normal parameters."

    return {
        "risk_summary": risk_summary,
        "evidence": evidence,
        "feature_attribution": feature_attribution,
        "recommended_action": recommended_action,
    }


def generate_evidence_reports() -> pd.DataFrame:
    """Generate evidence reports by merging all pipeline outputs."""
    print("=" * 55)
    print("  Explainability Engine - Evidence Generator")
    print("=" * 55)

    data_dir = DATA_DIR

    # Step 1: Load all CSVs
    print("\n[1/2] Loading pipeline outputs...")
    trust_path = os.path.join(data_dir, "trust_scores.csv")
    trust_df = pd.read_csv(trust_path)
    trust_df["window"] = pd.to_datetime(trust_df["window"])

    drift_path = os.path.join(data_dir, "drift_results.csv")
    if os.path.exists(drift_path):
        drift_df = pd.read_csv(drift_path)
        drift_df["window"] = pd.to_datetime(drift_df["window"])
    else:
        drift_df = pd.DataFrame(columns=["device_id", "window", "drift_magnitude", "drift_class", "top_drifters"])

    policy_path = os.path.join(data_dir, "policy_results.csv")
    if os.path.exists(policy_path):
        policy_df = pd.read_csv(policy_path)
        policy_df["window"] = pd.to_datetime(policy_df["window"])
    else:
        policy_df = pd.DataFrame(columns=["device_id", "window", "policy_status", "violations"])

    anomaly_path = os.path.join(data_dir, "anomaly_scores.csv")
    anomaly_df = pd.read_csv(anomaly_path)
    anomaly_df["window"] = pd.to_datetime(anomaly_df["window"])

    print(f"  Trust scores:   {len(trust_df)} rows")
    print(f"  Drift results:  {len(drift_df)} rows")
    print(f"  Policy results: {len(policy_df)} rows")
    print(f"  Anomaly scores: {len(anomaly_df)} rows")

    # Step 2: Merge all dataframes
    merged = trust_df.copy()

    # Merge drift results (only extra columns not already in trust_df)
    if not drift_df.empty:
        merged = merged.merge(
            drift_df[["device_id", "window", "drift_magnitude", "top_drifters"]],
            on=["device_id", "window"],
            how="left",
            suffixes=("", "_drift"),
        )
    else:
        merged["drift_magnitude"] = 0.0
        merged["top_drifters"] = "[]"

    # Merge policy results (only violations column)
    if not policy_df.empty:
        merged = merged.merge(
            policy_df[["device_id", "window", "violations"]],
            on=["device_id", "window"],
            how="left",
            suffixes=("", "_policy"),
        )
    else:
        merged["violations"] = "none"

    # Merge anomaly scores (only is_anomaly column)
    merged = merged.merge(
        anomaly_df[["device_id", "window", "is_anomaly"]],
        on=["device_id", "window"],
        how="left",
    )

    # Step 3: Fill missing values
    merged["drift_magnitude"] = merged["drift_magnitude"].fillna(0.0)
    merged["top_drifters"] = merged["top_drifters"].fillna("[]")
    merged["violations"] = merged["violations"].fillna("none")
    merged["drift_class"] = merged["drift_class"].fillna("DRIFT_NONE")
    merged["policy_status"] = merged["policy_status"].fillna("COMPLIANT")

    # Step 4: Apply build_evidence_text to each row
    print(f"\n[2/2] Generating evidence for {len(merged)} windows...")
    evidence_data = merged.apply(build_evidence_text, axis=1)
    evidence_df = pd.DataFrame(evidence_data.tolist())

    # Combine with merged data
    final_df = pd.concat([merged, evidence_df], axis=1)

    # Step 5: Select final columns and save
    output_columns = [
        "device_id", "device_type", "window", "trust_score_smoothed", "severity_smoothed",
        "risk_summary", "evidence", "feature_attribution", "recommended_action",
        "anomaly_score", "drift_class", "policy_status",
    ]

    final_df = final_df[output_columns]

    output_path = os.path.join(data_dir, "evidence_reports.csv")
    final_df.to_csv(output_path, index=False)

    # Step 6: Print summary
    print("\n" + "=" * 55)
    print("  EVIDENCE REPORTS")
    print("=" * 55)

    flagged = final_df[final_df["severity_smoothed"].isin(["Critical", "High", "Medium"])]

    for _, row in flagged.iterrows():
        print(f"\n  [{row['severity_smoothed'].upper()}] {row['device_id']} @ {row['window']}")
        print(f"    Trust: {row['trust_score_smoothed']}")
        print(f"    Summary: {row['risk_summary']}")
        print(f"    Evidence: {row['evidence']}")
        print(f"    Attribution: {row['feature_attribution']}")
        print(f"    Action: {row['recommended_action']}")

    print(f"\n  Total windows:  {len(final_df)}")
    print(f"  Flagged:        {len(flagged)}")
    print(f"  Clean:          {len(final_df) - len(flagged)}")
    print(f"\n  Saved to: {output_path}")
    print("=" * 55)

    return final_df


if __name__ == "__main__":
    generate_evidence_reports()
    print("\nExplainability Engine complete. Reports saved to data/evidence_reports.csv")
