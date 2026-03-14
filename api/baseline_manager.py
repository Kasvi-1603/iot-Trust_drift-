"""
baseline_manager.py
===================
Self-correcting adaptive baseline using feedback from
drift detection, policy evaluation, and risk scoring.

Only updates the baseline when traffic looks genuinely normal —
blocks updates during attacks, strong drift, or policy violations.
"""

from typing import Dict

ALPHA = 0.08   # slow learning rate to avoid baseline poisoning


def should_update_baseline(drift_result, policy_result, risk_score: float) -> bool:
    """
    Gate: decide whether current traffic is safe to learn from.
    Returns False (block update) if any anomaly signal is present.
    """
    # Don't learn from risky windows
    if risk_score >= 40:
        return False

    # Don't learn from strong drift
    drift_class = (
        drift_result.get("drift_class", "DRIFT_NONE")
        if isinstance(drift_result, dict)
        else getattr(drift_result, "drift_class", "DRIFT_NONE")
    )
    if drift_class == "DRIFT_STRONG":
        return False

    # Don't learn from windows with multiple policy violations
    total_violations = (
        policy_result.get("total_violations", 0)
        if isinstance(policy_result, dict)
        else getattr(policy_result, "total_violations", 0)
    )
    if total_violations > 1:
        return False

    return True


def adaptive_update(baseline: Dict, current_row: Dict) -> Dict:
    """
    Exponential moving average update for each feature's mean and std.
    Uses ALPHA = 0.08 so the baseline shifts slowly over time.
    """
    for feature in baseline:
        old_mean = baseline[feature]["mean"]
        old_std  = baseline[feature]["std"]
        value    = float(current_row.get(feature, 0))

        new_mean = ALPHA * value + (1 - ALPHA) * old_mean
        deviation = abs(value - old_mean)
        new_std  = ALPHA * deviation + (1 - ALPHA) * old_std

        baseline[feature]["mean"] = new_mean
        baseline[feature]["std"]  = max(new_std, 1e-6)   # prevent zero std

    return baseline


def feedback_update(
    baseline: Dict,
    current_row: Dict,
    drift_result,
    policy_result,
    risk_score: float,
):
    """
    Main entry point.
    Returns (updated_baseline, was_updated: bool).
    """
    if should_update_baseline(drift_result, policy_result, risk_score):
        baseline = adaptive_update(baseline, current_row)
        return baseline, True
    return baseline, False

