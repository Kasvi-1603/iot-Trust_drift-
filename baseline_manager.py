"""
baseline_manager.py
===================

Self-correcting adaptive baseline using feedback from
drift detection, policy evaluation, and risk scoring.
"""

from typing import Dict
from datetime import datetime

ALPHA = 0.08   # slow learning to avoid poisoning


def should_update_baseline(drift_result, policy_result, risk_score):

    if risk_score >= 40:
        return False

    if drift_result.drift_class == "DRIFT_STRONG":
        return False

    if policy_result.total_violations > 1:
        return False

    return True


def adaptive_update(baseline: Dict, current_row: Dict):

    for feature in baseline:

        old_mean = baseline[feature]["mean"]
        old_std = baseline[feature]["std"]

        value = float(current_row.get(feature, 0))

        new_mean = ALPHA * value + (1 - ALPHA) * old_mean

        deviation = abs(value - old_mean)

        new_std = ALPHA * deviation + (1 - ALPHA) * old_std

        baseline[feature]["mean"] = new_mean
        baseline[feature]["std"] = max(new_std, 1e-6)

    return baseline


def feedback_update(
        baseline,
        current_row,
        drift_result,
        policy_result,
        risk_score
):

    if should_update_baseline(drift_result, policy_result, risk_score):

        baseline = adaptive_update(baseline, current_row)

        return baseline, True

    return baseline, False