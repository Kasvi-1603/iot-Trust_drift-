"""
policy_engine.py
================
Enhanced policy engine for visualization dashboards.
"""

from dataclasses import dataclass, field
from typing import List, Set, Dict
import os, sys
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
from config.device_profiles import get_profile, is_internal_ip
from datetime import datetime


COMPLIANT      = "COMPLIANT"
SOFT_DRIFT     = "SOFT_DRIFT"
HARD_VIOLATION = "HARD_VIOLATION"


POLICY_PENALTY = {
    COMPLIANT:      0,
    SOFT_DRIFT:    15,
    HARD_VIOLATION: 40,
}


def policy_risk(status: str) -> str:

    if status == COMPLIANT:
        return "LOW"

    if status == SOFT_DRIFT:
        return "MEDIUM"

    return "HIGH"


@dataclass
class PolicyResult:

    device_id: str
    device_type: str
    window_start: str

    status: str

    risk_level: str

    violations: List[str] = field(default_factory=list)

    violation_types: List[str] = field(default_factory=list)

    violation_count: int = 0

    penalty: int = 0

    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


def evaluate_policy(
    device_id: str,
    device_type: str,
    window_start: str,
    feature_row: dict,
    raw_flows: List[dict],
) -> PolicyResult:

    profile = get_profile(device_type)

    violations = []
    violation_types = []


    # --- Protocol check ---

    observed_protocols: Set[str] = {f["protocol"] for f in raw_flows}

    bad_protocols = observed_protocols - profile["allowed_protocols"]

    if bad_protocols:

        violations.append(
            f"Unauthorized protocol(s): {bad_protocols}"
        )

        violation_types.append("protocol_violation")


    # --- Port check ---

    observed_ports: Set[int] = {int(f["dst_port"]) for f in raw_flows}

    bad_ports = observed_ports - profile["allowed_ports"]

    if bad_ports:

        violations.append(
            f"Unauthorized port(s): {bad_ports}"
        )

        violation_types.append("port_violation")


    # --- Destination IP check ---

    observed_ips: Set[str] = {f["dst_ip"] for f in raw_flows}

    bad_ips = {
        ip for ip in observed_ips
        if ip not in profile["allowed_dst_ips"] and not is_internal_ip(ip)
    }

    if bad_ips:

        violations.append(
            f"Unknown external destination(s): {bad_ips}"
        )

        violation_types.append("destination_violation")


    # --- Bandwidth check ---

    total_bytes = float(feature_row.get("total_bytes_out", 0))

    bw_limit = profile["bandwidth_max_bytes"] * 1.5

    if total_bytes > bw_limit:

        violations.append(
            f"Volume violation: {total_bytes:.0f} > {bw_limit:.0f}"
        )

        violation_types.append("bandwidth_violation")


    # --- Direction check ---

    observed_dirs: Set[str] = {f.get("direction", "outbound") for f in raw_flows}

    bad_dirs = observed_dirs - profile["expected_directions"]

    if bad_dirs:

        violations.append(
            f"Unexpected traffic direction(s): {bad_dirs}"
        )

        violation_types.append("direction_violation")


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
        risk_level=policy_risk(status),
        violations=violations,
        violation_types=violation_types,
        violation_count=n,
        penalty=POLICY_PENALTY[status],
    )