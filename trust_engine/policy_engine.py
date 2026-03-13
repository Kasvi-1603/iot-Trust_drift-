"""
policy_engine.py
================
Evaluates per-hour feature windows against device policy rules.

Input : feature window dict (from feature_extractor output)
        + raw flows for that window (list of dicts from full_dataset)
Output: PolicyResult dataclass

Violation levels:
  COMPLIANT      - 0 violations
  SOFT_DRIFT     - 1 violation
  HARD_VIOLATION - 2+ violations
"""

from dataclasses import dataclass, field
from typing import List, Set
from trust_engine.device_profiles import get_profile, is_internal_ip


COMPLIANT      = "COMPLIANT"
SOFT_DRIFT     = "SOFT_DRIFT"
HARD_VIOLATION = "HARD_VIOLATION"

# Trust score deductions
POLICY_PENALTY = {
    COMPLIANT:      0,
    SOFT_DRIFT:    15,
    HARD_VIOLATION: 40,
}


@dataclass
class PolicyResult:
    device_id:    str
    device_type:  str
    window_start: str
    status:       str               # COMPLIANT | SOFT_DRIFT | HARD_VIOLATION
    violations:   List[str] = field(default_factory=list)
    penalty:      int = 0


def evaluate_policy(
    device_id:    str,
    device_type:  str,
    window_start: str,
    feature_row:  dict,             # 1-hour aggregated features
    raw_flows:    List[dict],       # individual flow records in that window
) -> PolicyResult:
    """
    Run all policy checks and return a PolicyResult.

    feature_row keys expected:
        total_bytes_out, num_flows, unique_dst_ips,
        unique_dst_ports, unique_protocols, external_ratio
    raw_flows keys expected:
        dst_ip, protocol, dst_port, direction
    """
    profile    = get_profile(device_type)
    violations = []

    # --- 1. Protocol check ---
    observed_protocols: Set[str] = {f["protocol"] for f in raw_flows}
    bad_protocols = observed_protocols - profile["allowed_protocols"]
    if bad_protocols:
        violations.append(
            f"Unauthorized protocol(s): {bad_protocols}. "
            f"Allowed: {profile['allowed_protocols']}"
        )

    # --- 2. Port check ---
    observed_ports: Set[int] = {int(f["dst_port"]) for f in raw_flows}
    bad_ports = observed_ports - profile["allowed_ports"]
    if bad_ports:
        violations.append(
            f"Unauthorized port(s): {bad_ports}. "
            f"Allowed: {profile['allowed_ports']}"
        )

    # --- 3. Destination IP check ---
    observed_ips: Set[str] = {f["dst_ip"] for f in raw_flows}
    # Allowed if in explicit whitelist OR is an internal RFC-1918 address
    bad_ips = {
        ip for ip in observed_ips
        if ip not in profile["expected_dst_ips"] and not is_internal_ip(ip)
    }
    if bad_ips:
        violations.append(
            f"Unknown external destination(s): {bad_ips}"
        )

    # --- 4. Volume check (50% grace buffer) ---
    total_bytes = float(feature_row.get("total_bytes_out", 0))
    bw_limit    = profile["bandwidth_max_bytes"] * 1.5
    if total_bytes > bw_limit:
        violations.append(
            f"Volume violation: {total_bytes:.0f} bytes "
            f"exceeds limit {bw_limit:.0f} ({total_bytes/bw_limit:.1f}×)"
        )

    # --- 5. Direction check ---
    observed_dirs: Set[str] = {f.get("direction", "outbound") for f in raw_flows}
    bad_dirs = observed_dirs - profile["expected_directions"]
    if bad_dirs:
        violations.append(
            f"Unexpected traffic direction(s): {bad_dirs}"
        )

    n = len(violations)
    if n == 0:
        status = COMPLIANT
    elif n == 1:
        status = SOFT_DRIFT
    else:
        status = HARD_VIOLATION

    return PolicyResult(
        device_id=device_id,
        device_type=device_type,
        window_start=window_start,
        status=status,
        violations=violations,
        penalty=POLICY_PENALTY[status],
    )