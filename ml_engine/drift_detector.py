"""
drift_detector.py
=================
Enhanced drift detector supporting visualization dashboards.
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

    feature_zscores: Dict[str, float] = field(default_factory=dict)

    top_drifters: List[Tuple[str, float]] = field(default_factory=list)

    penalty: int = 0

    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


def _zscore(current: float, mean: float, std: float) -> float:

    if std < 1e-9:
        return 0.0 if abs(current - mean) < 1e-9 else Z_CAP

    return min(abs(current - mean) / std, Z_CAP)


def compute_drift(
    device_id: str,
    window_start: str,
    current_row: dict,
    baseline: dict,
) -> DriftResult:

    zscores: Dict[str, float] = {}

    for feat in DRIFT_FEATURES:

        if feat not in baseline:
            continue

        current_val = float(current_row.get(feat, 0))
        mean = float(baseline[feat]["mean"])
        std = float(baseline[feat]["std"])

        zscores[feat] = _zscore(current_val, mean, std)

    if not zscores:

        return DriftResult(
            device_id=device_id,
            window_start=window_start,
            drift_class=DRIFT_NONE,
            drift_magnitude=0.0,
            risk_level="LOW",
            penalty=0,
        )

    magnitude = sum(zscores.values()) / len(zscores)

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
        feature_zscores={k: round(v, 2) for k, v in zscores.items()},
        top_drifters=[(k, round(v, 2)) for k, v in top_drifters],
        penalty=DRIFT_PENALTY[drift_class],
    )