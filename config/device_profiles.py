"""
Device Profiles — Defines "what is normal" for each device type.

Used by:
  - Policy Engine   -> checks if device violates its allowed behavior
  - Drift Detector  -> knows baseline thresholds per device type
  - Evidence Generator -> explains WHY something is anomalous
"""

import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")


# ─────────────────────────────────────────────
# HELPER: Check if IP is internal (RFC-1918)
# ─────────────────────────────────────────────

def is_internal_ip(ip: str) -> bool:
    """Return True if IP is a private/internal address (RFC-1918)."""
    return (
        ip.startswith("10.")
        or ip.startswith("192.168.")
        or ip.startswith("172.16.") or ip.startswith("172.17.")
        or ip.startswith("172.18.") or ip.startswith("172.19.")
        or ip.startswith("172.20.") or ip.startswith("172.21.")
        or ip.startswith("172.22.") or ip.startswith("172.23.")
        or ip.startswith("172.24.") or ip.startswith("172.25.")
        or ip.startswith("172.26.") or ip.startswith("172.27.")
        or ip.startswith("172.28.") or ip.startswith("172.29.")
        or ip.startswith("172.30.") or ip.startswith("172.31.")
        or ip == "127.0.0.1"
    )


# ─────────────────────────────────────────────
# DEVICE PROFILES
# ─────────────────────────────────────────────

DEVICE_PROFILES = {

    # CCTV Camera — streams video via RTSP to internal NVR
    "CCTV": {
        "description": "IP Camera streaming to internal NVR",
        "allowed_protocols": {"RTSP"},
        "allowed_ports": {554},
        "allowed_dst_ips": {"192.168.1.100"},
        "allow_external": False,
        "bytes_range": (50000, 250000),
        "bandwidth_max_bytes": 15_000_000,       # max hourly total bytes
        "max_unique_dst_ips": 1,
        "max_unique_dst_ports": 1,
        "expected_directions": {"outbound"},
        "baseline_features": {
            "total_bytes_out": {"expected_mean": 9_145_000, "alert_multiplier": 3},
            "total_packets_out": {"expected_mean": 9_126, "alert_multiplier": 3},
            "unique_dst_ips": {"expected_mean": 1, "hard_max": 2},
            "external_ratio": {"expected_mean": 0.0, "hard_max": 0.0},
        },
    },

    # Router / DNS Forwarder — forwards DNS queries to Google DNS
    "Router": {
        "description": "DNS forwarder to Google DNS",
        "allowed_protocols": {"DNS"},
        "allowed_ports": {53},
        "allowed_dst_ips": {"8.8.8.8", "8.8.4.4"},
        "allow_external": True,
        "bytes_range": (100, 15000),
        "bandwidth_max_bytes": 600_000,           # max hourly total bytes
        "max_unique_dst_ips": 2,
        "max_unique_dst_ports": 1,
        "expected_directions": {"outbound"},
        "baseline_features": {
            "total_bytes_out": {"expected_mean": 478_000, "alert_multiplier": 3},
            "total_packets_out": {"expected_mean": 867, "alert_multiplier": 3},
            "unique_dst_ips": {"expected_mean": 2, "hard_max": 3},
            "external_ratio": {"expected_mean": 1.0, "hard_min": 0.9},
        },
    },

    # Access Controller — badge reader authenticating to internal server
    "AccessController": {
        "description": "Badge reader authenticating to internal server",
        "allowed_protocols": {"HTTPS"},
        "allowed_ports": {443},
        "allowed_dst_ips": {"192.168.1.50"},
        "allow_external": False,
        "bytes_range": (500, 4000),
        "bandwidth_max_bytes": 50_000,            # max hourly total bytes
        "max_unique_dst_ips": 1,
        "max_unique_dst_ports": 1,
        "expected_directions": {"outbound"},
        "baseline_features": {
            "total_bytes_out": {"expected_mean": 24_000, "alert_multiplier": 3},
            "total_packets_out": {"expected_mean": 55, "alert_multiplier": 3},
            "unique_dst_ips": {"expected_mean": 1, "hard_max": 2},
            "external_ratio": {"expected_mean": 0.0, "hard_max": 0.0},
        },
    },
}


# ─────────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────────

def get_profile(device_type: str) -> dict:
    """Get the profile for a device type. Returns None if not found."""
    return DEVICE_PROFILES.get(device_type, None)


def get_all_device_types() -> list:
    """Return list of all known device types."""
    return list(DEVICE_PROFILES.keys())


if __name__ == "__main__":
    print("=" * 55)
    print("  Device Profiles")
    print("=" * 55)

    for dtype in DEVICE_PROFILES:
        p = DEVICE_PROFILES[dtype]
        print(f"\n  {dtype}: {p['description']}")
        print(f"    Protocols:      {p['allowed_protocols']}")
        print(f"    Ports:          {p['allowed_ports']}")
        print(f"    Destinations:   {p['allowed_dst_ips']}")
        print(f"    External:       {'Yes' if p['allow_external'] else 'No'}")
        print(f"    Bytes range:    {p['bytes_range'][0]:,} - {p['bytes_range'][1]:,}")
        print(f"    BW max/hr:      {p['bandwidth_max_bytes']:,}")
        print(f"    Max dst IPs:    {p['max_unique_dst_ips']}")
        print(f"    Directions:     {p['expected_directions']}")

    print("\n  is_internal_ip tests:")
    print(f"    192.168.1.100 -> {is_internal_ip('192.168.1.100')}")
    print(f"    8.8.8.8       -> {is_internal_ip('8.8.8.8')}")
    print(f"    203.0.113.50  -> {is_internal_ip('203.0.113.50')}")

    print("\n" + "=" * 55)
