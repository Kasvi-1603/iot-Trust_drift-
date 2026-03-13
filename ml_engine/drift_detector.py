"""
drift_detector.py
=================
Three-fold drift detector:
1. Statistical drift (baseline z-score)
2. Behavioral pattern drift
3. Temporal drift (window-to-window)
"""

from dataclasses import dataclass, field
from typing import Dict, List, Tuple
from datetime import datetime


DRIFT_NONE   = "DRIFT_NONE"
DRIFT_MILD   = "DRIFT_MILD"
DRIFT_STRONG = "DRIFT_STRONG"


DRIFT_PENALTY = {
    DRIFT_NONE:   0,
    DRIFT_MILD:  10,
    DRIFT_STRONG: 20,
}


Z_CAP = 100.0


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


def drift_risk_level(magnitude: float) -> str:
    if magnitude < 1.5:
        return "LOW"
    elif magnitude < 3:
        return "MEDIUM"
    else:
        return "HIGH"


@dataclass
class DriftResult:

    device_id: str
    window_start: str

    drift_class: str
    drift_magnitude: float
    risk_level: str

    # Three drift components
    statistical_score: float = 0.0
    behavioral_score: float = 0.0
    temporal_score: float = 0.0

    feature_zscores: Dict[str, float] = field(default_factory=dict)
    top_drifters: List[Tuple[str, float]] = field(default_factory=list)

    penalty: int = 0

    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


def _zscore(current: float, mean: float, std: float) -> float:

    if std < 1e-9:
        return 0.0 if abs(current - mean) < 1e-9 else Z_CAP

    return min(abs(current - mean) / std, Z_CAP)


# ---------- 1️⃣ Statistical Drift ----------

def compute_statistical_drift(current_row, baseline):

    zscores = {}

    for feat in DRIFT_FEATURES:

        if feat not in baseline:
            continue

        current_val = float(current_row.get(feat, 0))
        mean = float(baseline[feat]["mean"])
        std = float(baseline[feat]["std"])

        zscores[feat] = _zscore(current_val, mean, std)

    if not zscores:
        return 0.0, {}

    magnitude = sum(zscores.values()) / len(zscores)

    return magnitude, zscores


# ---------- 2️⃣ Behavioral Drift ----------

def compute_behavioral_drift(zscores):

    # Count how many features have strong anomaly
    high_anomalies = sum(1 for z in zscores.values() if z > 2)

    behavioral_score = high_anomalies / max(len(zscores), 1) * 5

    return behavioral_score


# ---------- 3️⃣ Temporal Drift ----------

def compute_temporal_drift(current_row, prev_row):

    if not prev_row:
        return 0.0

    diffs = []

    for feat in DRIFT_FEATURES:

        curr = float(current_row.get(feat, 0))
        prev = float(prev_row.get(feat, 0))

        diff = abs(curr - prev)

        diffs.append(diff)

    if not diffs:
        return 0.0

    return sum(diffs) / len(diffs) / 100


def compute_drift(
    device_id: str,
    window_start: str,
    current_row: dict,
    baseline: dict,
    prev_row: dict = None,
) -> DriftResult:

    # --- Statistical drift ---
    stat_score, zscores = compute_statistical_drift(current_row, baseline)

    # --- Behavioral drift ---
    beh_score = compute_behavioral_drift(zscores)

    # --- Temporal drift ---
    temp_score = compute_temporal_drift(current_row, prev_row)

    # Combined magnitude
    magnitude = (stat_score + beh_score + temp_score) / 3

    if magnitude < 1.5:
        drift_class = DRIFT_NONE
    elif magnitude < 3:
        drift_class = DRIFT_MILD
    else:
        drift_class = DRIFT_STRONG

    risk_level = drift_risk_level(magnitude)

    top_drifters = sorted(zscores.items(), key=lambda x: x[1], reverse=True)[:3]

    return DriftResult(
        device_id=device_id,
        window_start=window_start,
        drift_class=drift_class,
        drift_magnitude=round(magnitude, 2),
        risk_level=risk_level,

        statistical_score=round(stat_score,2),
        behavioral_score=round(beh_score,2),
        temporal_score=round(temp_score,2),

        feature_zscores={k: round(v, 2) for k, v in zscores.items()},
        top_drifters=[(k, round(v, 2)) for k, v in top_drifters],

        penalty=DRIFT_PENALTY[drift_class],
    )