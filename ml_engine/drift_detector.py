"""
drift_detector.py
=================
Computes per-feature z-scores by comparing the current 1-hour window
against the device's learned baseline statistics.

Drift classes:
  DRIFT_NONE   - avg z-score < 1.5
  DRIFT_MILD   - avg z-score 1.5 - 3.0
  DRIFT_STRONG - avg z-score > 3.0

Drift score deductions for trust engine:
  DRIFT_NONE   ->  0
  DRIFT_MILD   -> -10
  DRIFT_STRONG -> -20
"""

import os
import pandas as pd
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")

DRIFT_NONE   = "DRIFT_NONE"
DRIFT_MILD   = "DRIFT_MILD"
DRIFT_STRONG = "DRIFT_STRONG"

DRIFT_PENALTY = {
    DRIFT_NONE:   0,
    DRIFT_MILD:  10,
    DRIFT_STRONG: 20,
}

# Z-score cap when std ≈ 0 (any deviation = infinite drift)
Z_CAP = 100.0

# Features evaluated against learned baseline
DRIFT_FEATURES = [
    "total_bytes_out",
    "total_packets_out",
    "avg_bytes_per_flow",
    "num_flows",
    "unique_dst_ips",
    "unique_dst_ports",
    "unique_protocols",
    "external_ratio",
    "avg_duration",
]


@dataclass
class DriftResult:
    device_id:       str
    window_start:    str
    drift_class:     str                              # DRIFT_NONE | DRIFT_MILD | DRIFT_STRONG
    drift_magnitude: float                            # average z-score across all features
    feature_zscores: Dict[str, float] = field(default_factory=dict)
    top_drifters:    List[Tuple[str, float]] = field(default_factory=list)
    penalty:         int = 0


def _zscore(current: float, mean: float, std: float) -> float:
    """Z-score with cap when std is near-zero."""
    if std < 1e-9:
        return 0.0 if abs(current - mean) < 1e-9 else Z_CAP
    return min(abs(current - mean) / std, Z_CAP)


def compute_drift(
    device_id:    str,
    window_start: str,
    current_row:  dict,    # 1-hour feature window
    baseline:     dict,    # {feature: {"mean": float, "std": float}}
) -> DriftResult:
    """
    Compare current_row against baseline stats.

    baseline format:
      {
        "total_bytes_out": {"mean": 170000.0, "std": 20000.0},
        "unique_dst_ips":  {"mean": 1.0,      "std": 0.0},
        ...
      }
    """
    zscores: Dict[str, float] = {}

    for feat in DRIFT_FEATURES:
        if feat not in baseline:
            continue
        current_val = float(current_row.get(feat, 0))
        mean        = float(baseline[feat]["mean"])
        std         = float(baseline[feat]["std"])
        zscores[feat] = _zscore(current_val, mean, std)

    if not zscores:
        return DriftResult(
            device_id=device_id,
            window_start=window_start,
            drift_class=DRIFT_NONE,
            drift_magnitude=0.0,
            penalty=0,
        )

    magnitude = sum(zscores.values()) / len(zscores)

    if magnitude < 1.5:
        drift_class = DRIFT_NONE
    elif magnitude < 3.0:
        drift_class = DRIFT_MILD
    else:
        drift_class = DRIFT_STRONG

    # Top 3 drifting features (fed to explainability engine)
    top_drifters = sorted(zscores.items(), key=lambda x: x[1], reverse=True)[:3]

    return DriftResult(
        device_id=device_id,
        window_start=window_start,
        drift_class=drift_class,
        drift_magnitude=round(magnitude, 2),
        feature_zscores={k: round(v, 2) for k, v in zscores.items()},
        top_drifters=[(k, round(v, 2)) for k, v in top_drifters],
        penalty=DRIFT_PENALTY[drift_class],
    )


# ============================================
# MAIN — Run drift detection on all windows
# ============================================

if __name__ == "__main__":
    from ml_engine.anomaly_detector import load_features, split_baseline_and_full, compute_baseline

    print("=" * 55)
    print("  Drift Detector - Z-Score Analysis")
    print("=" * 55)

    # Load features
    print("\n[1/3] Loading feature vectors...")
    features = load_features("feature_vectors.csv")
    print(f"  Loaded {len(features)} feature windows")

    # Split baseline
    print("\n[2/3] Computing baseline statistics...")
    baseline, full = split_baseline_and_full(features, baseline_hours=48)
    baseline_stats = compute_baseline(baseline)
    print(f"  Baseline: {len(baseline)} windows")
    print(f"  Devices:  {list(baseline_stats.keys())}")

    # Run drift detection per window
    print(f"\n[3/3] Computing drift for all {len(full)} windows...")
    results = []

    for _, row in full.iterrows():
        device_id = row["device_id"]
        window = str(row["window"])

        # Get this device's baseline
        if device_id not in baseline_stats:
            continue

        result = compute_drift(
            device_id=device_id,
            window_start=window,
            current_row=row.to_dict(),
            baseline=baseline_stats[device_id],
        )

        results.append({
            "device_id": result.device_id,
            "window": result.window_start,
            "drift_magnitude": result.drift_magnitude,
            "drift_class": result.drift_class,
            "top_drifters": str(result.top_drifters),
            "penalty": result.penalty,
        })

    # Save results
    results_df = pd.DataFrame(results)
    output_path = os.path.join(DATA_DIR, "drift_results.csv")
    results_df.to_csv(output_path, index=False)

    # Summary
    print("\n" + "=" * 55)
    print("  DRIFT DETECTION RESULTS")
    print("=" * 55)

    for dev in sorted(results_df["device_id"].unique()):
        dev_data = results_df[results_df["device_id"] == dev]
        none_ct = len(dev_data[dev_data["drift_class"] == DRIFT_NONE])
        mild_ct = len(dev_data[dev_data["drift_class"] == DRIFT_MILD])
        strong_ct = len(dev_data[dev_data["drift_class"] == DRIFT_STRONG])
        print(f"\n  {dev}:")
        print(f"    DRIFT_NONE:   {none_ct}")
        print(f"    DRIFT_MILD:   {mild_ct}")
        print(f"    DRIFT_STRONG: {strong_ct}")
        # Show drifting windows
        drifting = dev_data[dev_data["drift_class"] != DRIFT_NONE]
        for _, d in drifting.iterrows():
            print(f"    -> [{d['drift_class']}] {d['window']}  magnitude={d['drift_magnitude']}  {d['top_drifters']}")

    print(f"\n  Saved to: {output_path}")
    print("=" * 55)