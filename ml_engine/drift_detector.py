"""
drift_detector.py
=================
Three-fold drift detector:
  1. Statistical drift  — baseline z-score per feature
  2. Behavioral drift   — fraction of features in strong anomaly
  3. Temporal drift     — window-to-window rate of change
"""

from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional
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

    # ── Three drift components ──
    statistical_score: float = 0.0
    behavioral_score:  float = 0.0
    temporal_score:    float = 0.0

    feature_zscores: Dict[str, float] = field(default_factory=dict)
    top_drifters:    List[Tuple[str, float]] = field(default_factory=list)

    penalty: int = 0

    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


# ─────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────

def _zscore(current: float, mean: float, std: float) -> float:
    if std < 1e-9:
        return 0.0 if abs(current - mean) < 1e-9 else Z_CAP
    return min(abs(current - mean) / std, Z_CAP)


# ─────────────────────────────────────────────────────────
# 1️⃣  Statistical Drift — baseline z-score
# ─────────────────────────────────────────────────────────

def compute_statistical_drift(
    current_row: dict,
    baseline: dict,
) -> Tuple[float, Dict[str, float]]:
    """
    Compare each feature against the learned baseline using z-scores.
    Returns (mean_zscore, {feature: zscore}).
    """
    zscores: Dict[str, float] = {}

    for feat in DRIFT_FEATURES:
        if feat not in baseline:
            continue
        current_val = float(current_row.get(feat, 0))
        mean = float(baseline[feat]["mean"])
        std  = float(baseline[feat]["std"])
        zscores[feat] = _zscore(current_val, mean, std)

    if not zscores:
        return 0.0, {}

    magnitude = sum(zscores.values()) / len(zscores)
    return magnitude, zscores


# ─────────────────────────────────────────────────────────
# 2️⃣  Behavioral Drift — breadth of anomaly
# ─────────────────────────────────────────────────────────

def compute_behavioral_drift(zscores: Dict[str, float]) -> float:
    """
    Score based on *how many* features are strongly anomalous (z > 2).
    Returns a value on the same scale as the z-score magnitude.
    """
    if not zscores:
        return 0.0
    high_anomalies = sum(1 for z in zscores.values() if z > 2)
    # Normalise to [0, 5] — comparable to z-score scale
    behavioral_score = (high_anomalies / len(zscores)) * 5
    return behavioral_score


# ─────────────────────────────────────────────────────────
# 3️⃣  Temporal Drift — window-to-window change rate
# ─────────────────────────────────────────────────────────

def compute_temporal_drift(
    current_row: dict,
    prev_row: Optional[dict],
) -> float:
    """
    Measure how quickly features are changing relative to the previous window.
    Returns a normalised score on the same scale as z-score magnitude.
    """
    if not prev_row:
        return 0.0

    diffs = []
    for feat in DRIFT_FEATURES:
        curr = float(current_row.get(feat, 0))
        prev = float(prev_row.get(feat, 0))
        diffs.append(abs(curr - prev))

    if not diffs:
        return 0.0

    # Divide by 100 to bring into a comparable range with z-scores
    return sum(diffs) / len(diffs) / 100.0


# ─────────────────────────────────────────────────────────
# Public API — combined compute_drift
# ─────────────────────────────────────────────────────────

def compute_drift(
    device_id: str,
    window_start: str,
    current_row: dict,
    baseline: dict,
    prev_row: Optional[dict] = None,
) -> DriftResult:
    """
    Run all three drift components and combine into a single DriftResult.

    Args:
        device_id:    identifier of the device being scored
        window_start: ISO timestamp of the current window
        current_row:  feature vector for this window
        baseline:     {feature: {mean, std}} learned baseline
        prev_row:     feature vector from the immediately preceding window
                      (optional — enables temporal drift scoring)
    """

    # ── 1. Statistical ──
    stat_score, zscores = compute_statistical_drift(current_row, baseline)

    # Early exit if no baseline features available
    if not zscores:
        return DriftResult(
            device_id=device_id,
            window_start=window_start,
            drift_class=DRIFT_NONE,
            drift_magnitude=0.0,
            risk_level="LOW",
            statistical_score=0.0,
            behavioral_score=0.0,
            temporal_score=0.0,
            penalty=0,
        )

    # ── 2. Behavioral ──
    beh_score = compute_behavioral_drift(zscores)

    # ── 3. Temporal ──
    temp_score = compute_temporal_drift(current_row, prev_row)

    # ── Combined magnitude (equal weight) ──
    magnitude = (stat_score + beh_score + temp_score) / 3.0

    # ── Classification ──
    if magnitude < 1.5:
        drift_class = DRIFT_NONE
    elif magnitude < 3.0:
        drift_class = DRIFT_MILD
    else:
        drift_class = DRIFT_STRONG

    risk_level   = drift_risk_level(magnitude)
    top_drifters = sorted(zscores.items(), key=lambda x: x[1], reverse=True)[:3]

    return DriftResult(
        device_id=device_id,
        window_start=window_start,
        drift_class=drift_class,
        drift_magnitude=round(magnitude, 2),
        risk_level=risk_level,
        statistical_score=round(stat_score, 2),
        behavioral_score=round(beh_score, 2),
        temporal_score=round(temp_score, 2),
        feature_zscores={k: round(v, 2) for k, v in zscores.items()},
        top_drifters=[(k, round(v, 2)) for k, v in top_drifters],

        penalty=DRIFT_PENALTY[drift_class],
    )
