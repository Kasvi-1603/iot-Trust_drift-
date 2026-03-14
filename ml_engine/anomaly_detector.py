"""
ML Engine — Baseline Learning + Device Behavioral Profiler
  - Computes per-device baseline statistics (mean/std)
  - Trains SEPARATE Isolation Forest per device type (fingerprinting)
  - Scores all windows and outputs anomaly_score (0-1)
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")

FEATURE_COLS = [
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


# ============================================
# BASELINE LEARNING ENGINE
# ============================================

def compute_baseline(baseline_features):
    """
    Learn per-device baseline statistics (mean + std for each feature).
    Used by drift detector to compare current vs. historical behavior.
    
    Input:  DataFrame with baseline-period feature vectors
    Output: dict of { device_id: { feature: { mean, std } } }
    """
    stats = {}
    for device_id in baseline_features["device_id"].unique():
        device_data = baseline_features[baseline_features["device_id"] == device_id]
        device_stats = {}
        for feat in FEATURE_COLS:
            device_stats[feat] = {
                "mean": device_data[feat].mean(),
                "std": device_data[feat].std() if device_data[feat].std() > 0 else 1e-6,
            }
        stats[device_id] = device_stats
    return stats


# ============================================
# DEVICE BEHAVIORAL PROFILER (FINGERPRINTING)
# ============================================

def train_per_device_type(baseline_features):
    """
    Train SEPARATE Isolation Forest per device type.
    Each device type gets its own scaler + model = fingerprinting.
    
    CCTV model  -> knows CCTV normal (high bandwidth, RTSP, 1 dest)
    Router model -> knows Router normal (low bandwidth, DNS, 2 dests)
    AccessCtrl model -> knows AccessCtrl normal (tiny bandwidth, HTTPS, 1 dest)
    
    Input:  DataFrame with baseline feature vectors (unscaled)
    Output: dict of { device_type: { model, scaler } }
    """
    models = {}

    for device_type in baseline_features["device_type"].unique():
        # Filter baseline for THIS device type only
        type_data = baseline_features[baseline_features["device_type"] == device_type]
        X = type_data[FEATURE_COLS].values

        # Scale using ONLY this device type's data
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        # Train Isolation Forest on this device type's normal behavior
        model = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42,
        )
        model.fit(X_scaled)

        models[device_type] = {"model": model, "scaler": scaler}
        print(f"  [+] Trained model for {device_type} ({len(type_data)} baseline samples)")

    return models


def score_all_devices(models, all_features):
    """
    Score every device window using its MATCHING device-type model.
    
    CCTV windows -> scored by CCTV model
    Router windows -> scored by Router model
    AccessCtrl windows -> scored by AccessCtrl model
    
    Input:  models dict + DataFrame with all feature vectors (unscaled)
    Output: DataFrame with anomaly_score (0-1) and is_anomaly flag
    """
    results = []

    for device_type in all_features["device_type"].unique():
        if device_type not in models:
            print(f"  [!] No model for {device_type}, skipping")
            continue

        model = models[device_type]["model"]
        scaler = models[device_type]["scaler"]

        # Get all windows for this device type
        type_data = all_features[all_features["device_type"] == device_type].copy()
        X = type_data[FEATURE_COLS].values

        # Scale using THIS device type's scaler (not global)
        X_scaled = scaler.transform(X)

        # Score: decision_function returns raw scores (negative = more anomalous)
        raw_scores = model.decision_function(X_scaled)

        # Predict: 1 = normal, -1 = anomaly
        predictions = model.predict(X_scaled)

        type_data["raw_score"] = raw_scores
        type_data["is_anomaly"] = [1 if p == -1 else 0 for p in predictions]

        results.append(type_data)

    results_df = pd.concat(results, ignore_index=True)

    # Normalize raw_score to 0-1 (higher = more anomalous)
    mn = results_df["raw_score"].min()
    mx = results_df["raw_score"].max()
    results_df["anomaly_score"] = 1 - (results_df["raw_score"] - mn) / (mx - mn + 1e-10)

    # Confidence = how far from the decision boundary (|raw_score| normalised to 0-100)
    # High confidence -> clearly normal OR clearly anomalous
    # Low confidence  -> borderline / uncertain
    max_abs = results_df["raw_score"].abs().max() + 1e-10
    results_df["confidence"] = (results_df["raw_score"].abs() / max_abs * 100).round(1)

    return results_df


# ============================================
# HELPER: Load feature vectors
# ============================================

def load_features(filename="feature_vectors.csv"):
    """Load feature vectors from data/ folder."""
    path = os.path.join(DATA_DIR, filename)
    df = pd.read_csv(path)
    # Rename window_start to window if needed
    if "window_start" in df.columns:
        df = df.rename(columns={"window_start": "window"})
    # Parse window as datetime
    df["window"] = pd.to_datetime(df["window"])
    # Add device_type if missing (derive from device_id)
    if "device_type" not in df.columns:
        def get_device_type(device_id):
            if "CCTV" in device_id:
                return "CCTV"
            elif "Router" in device_id:
                return "Router"
            elif "Access" in device_id:
                return "AccessController"
            return "Unknown"
        df["device_type"] = df["device_id"].apply(get_device_type)
    return df


def split_baseline_and_full(features_df, baseline_hours=48):
    """
    Split features into baseline (first N hours) and full dataset.
    Baseline = assumed clean data for training.
    """
    min_time = features_df["window"].min()
    baseline_cutoff = min_time + pd.Timedelta(hours=baseline_hours)

    baseline = features_df[features_df["window"] < baseline_cutoff].copy()
    return baseline, features_df.copy()


# ============================================
# MAIN — Run anomaly detection pipeline
# ============================================

if __name__ == "__main__":
    print("=" * 55)
    print("  ML Engine — Anomaly Detection Pipeline")
    print("=" * 55)

    # Step 1: Load feature vectors
    print("\n[1/4] Loading feature vectors...")
    features = load_features("feature_vectors.csv")
    print(f"  Loaded {len(features)} feature vectors")
    print(f"  Devices: {features['device_id'].unique().tolist()}")
    print(f"  Time range: {features['window'].min()} to {features['window'].max()}")

    # Step 2: Split into baseline and full
    print("\n[2/4] Splitting baseline (first 48 hours)...")
    baseline, full = split_baseline_and_full(features, baseline_hours=48)
    print(f"  Baseline: {len(baseline)} windows")
    print(f"  Full:     {len(full)} windows")

    # Step 3: Compute baseline stats
    print("\n[3/4] Computing baseline statistics...")
    baseline_stats = compute_baseline(baseline)
    for dev_id, stats in baseline_stats.items():
        print(f"\n  {dev_id}:")
        print(f"    bytes_out  -> mean: {stats['total_bytes_out']['mean']:>12,.0f}  std: {stats['total_bytes_out']['std']:>10,.0f}")
        print(f"    packets    -> mean: {stats['total_packets_out']['mean']:>12,.0f}  std: {stats['total_packets_out']['std']:>10,.0f}")
        print(f"    unique_dst -> mean: {stats['unique_dst_ips']['mean']:>12,.1f}  std: {stats['unique_dst_ips']['std']:>10,.6f}")
        print(f"    ext_ratio  -> mean: {stats['external_ratio']['mean']:>12,.2f}  std: {stats['external_ratio']['std']:>10,.6f}")

    # Step 4: Train per-device-type models (FINGERPRINTING)
    print("\n[4/4] Training per-device-type Isolation Forest models...")
    models = train_per_device_type(baseline)

    # Step 5: Score all windows
    print("\nScoring all windows...")
    scored = score_all_devices(models, full)

    # Results
    print("\n" + "=" * 55)
    print("  ANOMALY DETECTION RESULTS")
    print("=" * 55)

    for device_id in scored["device_id"].unique():
        dev_data = scored[scored["device_id"] == device_id]
        normal_data = dev_data[dev_data["is_anomaly"] == 0]
        anomaly_data = dev_data[dev_data["is_anomaly"] == 1]
        print(f"\n  {device_id}:")
        print(f"    Total windows:   {len(dev_data)}")
        print(f"    Normal windows:  {len(normal_data)}")
        print(f"    Anomaly windows: {len(anomaly_data)}")
        if len(anomaly_data) > 0:
            print(f"    Anomaly scores:  min={anomaly_data['anomaly_score'].min():.3f}  max={anomaly_data['anomaly_score'].max():.3f}")
        if len(normal_data) > 0:
            print(f"    Normal scores:   min={normal_data['anomaly_score'].min():.3f}  max={normal_data['anomaly_score'].max():.3f}")

    # Save results
    output_path = os.path.join(DATA_DIR, "anomaly_scores.csv")
    scored.to_csv(output_path, index=False)
    print(f"\n  Saved to: {output_path}")
    print("=" * 55)
