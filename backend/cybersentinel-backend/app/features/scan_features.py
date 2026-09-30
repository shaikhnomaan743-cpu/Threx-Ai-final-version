from __future__ import annotations

import numpy as np
from typing import Dict, List, Any, Optional

from app.config import settings
from app.utils.ja_hasher import ip_port_to_5tuple


def compute_fan_out_unique_dst_ports(
    src_ip: str,
    flows_from_src: Dict[str, dict]
) -> int:
    """Count unique destination ports seen from a source IP.

    Used by port scan detector - horizontal scan shows many dst ports
    from the same src, vertical scan shows many dst hosts.

    Args:
        src_ip: Source IP address
        flows_from_src: Dict of flow_key -> flow_dict from this source

    Returns:
        Number of unique destination ports
    """
    unique_ports = set()
    for flow_key, flow_data in flows_from_src.items():
        dst_ports = flow_data.get("dst_ports", []) or []
        unique_ports.update(dst_ports)
        dp = flow_data.get("dst_port")
        if dp is not None:
            unique_ports.add(dp)
        raw = flow_data.get("raw_features") or {}
        if isinstance(raw, dict) and raw.get("unique_dst_ports"):
            # summarized scan flow: already counted many ports
            unique_ports.add(("summary", flow_key, int(raw["unique_dst_ports"])))
    # If any flow carried a summarized unique_dst_ports count, use the max of
    # enumerated ports and those summaries.
    summarized = 0
    enumerated = set()
    for p in unique_ports:
        if isinstance(p, tuple) and len(p) == 3 and p[0] == "summary":
            summarized = max(summarized, p[2])
        else:
            enumerated.add(p)
    return max(len(enumerated), summarized)


def compute_fan_out_unique_dst_hosts(
    src_ip: str,
    flows_from_src: Dict[str, dict]
) -> int:
    """Count unique destination hosts seen from a source IP.

    Args:
        src_ip: Source IP address
        flows_from_src: Dict of flow_key -> flow_dict from this source

    Returns:
        Number of unique destination IP addresses
    """
    unique_hosts = set()
    for flow_key, flow_data in flows_from_src.items():
        dst_ip = flow_data.get("dst_ip", "")
        unique_hosts.add(dst_ip)
    return len(unique_hosts)


def classify_scan_type(
    unique_dst_ports: int,
    unique_dst_hosts: int,
) -> str:
    """Classify scan type based on fan-out metrics.

    - Horizontal scan: Many destination ports, same/similar port
    - Vertical scan: Many destination hosts, same/similar host

    Returns:
        "horizontal", "vertical", or "mixed"
    """
    if unique_dst_ports > unique_dst_hosts:
        return "horizontal"
    elif unique_dst_hosts > unique_dst_ports:
        return "vertical"
    else:
        return "mixed"


def extract_scan_features(
    flow: dict,
    all_flows_from_src: Dict[str, dict]
) -> dict:
    """Extract port scan features from a flow.

    Args:
        flow: Individual flow state dict
        all_flows_from_src: All flows keyed by source IP

    Returns:
        Dict with fan-out and scan classification features
    """
    src_ip = flow.get("src_ip", "")
    dst_ports = flow.get("dst_ports", [])
    dst_ip = flow.get("dst_ip", "")

    unique_dst_ports = len(set(dst_ports)) if dst_ports else 0
    unique_dst_hosts = compute_fan_out_unique_dst_hosts(src_ip, all_flows_from_src)

    scan_type = classify_scan_type(unique_dst_ports, unique_dst_hosts)

    features = {
        "unique_dst_ports": unique_dst_ports,
        "unique_dst_hosts": unique_dst_hosts,
        "scan_type": scan_type,
        "is_horizontal_scan": scan_type == "horizontal",
        "is_vertical_scan": scan_type == "vertical",
        "fan_out_ratio": float(unique_dst_ports) / max(unique_dst_hosts, 1),
    }

    # Alert thresholds (configurable)
    features["port_scan_alert"] = (
        unique_dst_ports > settings.scan_unique_ports_threshold
        or unique_dst_hosts > settings.scan_unique_hosts_threshold
    )

    return features