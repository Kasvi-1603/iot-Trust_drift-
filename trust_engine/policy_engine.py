"""
Policy Engine
=============
Evaluates per-hour feature windows against device policy rules.

Input : feature window dict  +  raw flows for that window
Output: PolicyResult dataclass

Violation levels:
  COMPLIANT      - 0 violations
  SOFT_DRIFT     - 1 violation
  HARD_VIOLATION - 2+ violations
"""

import os
import pandas as pd
from dataclasses import dataclass, field
from typing import List, Set
from config.device_profiles import get_profile, is_internal_ip

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")

COMPLIANT      = "COMPLIANT"
SOFT_DRIFT     = "SOFT_DRIFT"
HARD_VIOLATION = "HARD_VIOLATION"

POLICY_PENALTY = {
    COMPLIANT:      0,
    SOFT_DRIFT:    15,
    HARD_VIOLATION: 40,
}


@dataclass
class PolicyResult:
    device_id:     str
    device_type:   str
    window:        str
    policy_status: str               # COMPLIANT | SOFT_DRIFT | HARD_VIOLATION
    violations:    List[str] = field(default_factory=list)
    penalty:       int = 0


def evaluate_policy(
    device_id:    str,
    device_type:  str,
    window:       str,
    feature_row:  dict,             # 1-hour aggregated features
    raw_flows:    List[dict],       # individual flow records in that window
) -> PolicyResult:
    """
    Run all policy checks and return a PolicyResult.
    """
    profile = get_profile(device_type)
    if profile is None:
        return PolicyResult(
            device_id=device_id, device_type=device_type,
            window=window, policy_status=COMPLIANT, penalty=0,
        )

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
    bad_ips = set()
    for ip in observed_ips:
        if ip not in profile["allowed_dst_ips"]:
            # If device is NOT allowed external, any non-whitelisted IP is bad
            if not profile["allow_external"]:
                bad_ips.add(ip)
            # If device IS allowed external, only flag non-internal non-whitelisted
            elif not is_internal_ip(ip):
                bad_ips.add(ip)
    if bad_ips:
        violations.append(
            f"Unknown destination(s): {bad_ips}"
        )

    # --- 4. Volume check (50% grace buffer) ---
    total_bytes = float(feature_row.get("total_bytes_out", 0))
    bw_limit = profile["bandwidth_max_bytes"] * 1.5
    if total_bytes > bw_limit:
        violations.append(
            f"Volume violation: {total_bytes:.0f} bytes "
            f"exceeds limit {bw_limit:.0f} ({total_bytes/bw_limit:.1f}x)"
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
        window=window,
        policy_status=status,
        violations=violations,
        penalty=POLICY_PENALTY[status],
    )


# ============================================
# MAIN — Run policy engine on all windows
# ============================================

if __name__ == "__main__":
    print("=" * 55)
    print("  Policy Engine - Violation Detection")
    print("=" * 55)

    # Load raw dataset (for per-flow checks)
    raw_path = os.path.join(DATA_DIR, "full_dataset.csv")
    print(f"\n[1/3] Loading raw dataset from {raw_path}...")
    raw_df = pd.read_csv(raw_path, parse_dates=["timestamp"])
    print(f"  Loaded {len(raw_df)} raw flows")

    # Load feature vectors (for volume checks)
    feat_path = os.path.join(DATA_DIR, "feature_vectors.csv")
    print(f"\n[2/3] Loading feature vectors from {feat_path}...")
    feat_df = pd.read_csv(feat_path)
    if "window_start" in feat_df.columns:
        feat_df = feat_df.rename(columns={"window_start": "window"})
    feat_df["window"] = pd.to_datetime(feat_df["window"])
    print(f"  Loaded {len(feat_df)} feature windows")

    # Derive device_type if missing
    if "device_type" not in feat_df.columns:
        def get_dtype(did):
            if "CCTV" in did: return "CCTV"
            elif "Router" in did: return "Router"
            elif "Access" in did: return "AccessController"
            return "Unknown"
        feat_df["device_type"] = feat_df["device_id"].apply(get_dtype)

    # Add hour column to raw_df for window matching
    raw_df["window"] = raw_df["timestamp"].dt.floor("h")

    # Run policy engine per window
    print(f"\n[3/3] Evaluating policy per window...")
    results = []

    for _, feat_row in feat_df.iterrows():
        device_id = feat_row["device_id"]
        device_type = feat_row["device_type"]
        window = feat_row["window"]

        # Get raw flows for this device + window
        mask = (raw_df["device_id"] == device_id) & (raw_df["window"] == window)
        window_flows = raw_df[mask].to_dict("records")

        result = evaluate_policy(
            device_id=device_id,
            device_type=device_type,
            window=str(window),
            feature_row=feat_row.to_dict(),
            raw_flows=window_flows,
        )

        results.append({
            "device_id": result.device_id,
            "device_type": result.device_type,
            "window": result.window,
            "policy_status": result.policy_status,
            "violations": "; ".join(result.violations) if result.violations else "none",
            "penalty": result.penalty,
        })

    # Save results
    results_df = pd.DataFrame(results)
    output_path = os.path.join(DATA_DIR, "policy_results.csv")
    results_df.to_csv(output_path, index=False)

    # Summary
    print("\n" + "=" * 55)
    print("  POLICY ENGINE RESULTS")
    print("=" * 55)

    for dev in sorted(results_df["device_id"].unique()):
        dev_data = results_df[results_df["device_id"] == dev]
        compliant = len(dev_data[dev_data["policy_status"] == COMPLIANT])
        soft = len(dev_data[dev_data["policy_status"] == SOFT_DRIFT])
        hard = len(dev_data[dev_data["policy_status"] == HARD_VIOLATION])
        print(f"\n  {dev}:")
        print(f"    COMPLIANT:      {compliant}")
        print(f"    SOFT_DRIFT:     {soft}")
        print(f"    HARD_VIOLATION: {hard}")
        # Show violations for non-compliant windows
        violations = dev_data[dev_data["policy_status"] != COMPLIANT]
        for _, v in violations.iterrows():
            print(f"    -> [{v['policy_status']}] {v['window']}: {v['violations']}")

    print(f"\n  Saved to: {output_path}")
    print("=" * 55)
