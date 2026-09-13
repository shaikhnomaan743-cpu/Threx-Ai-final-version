from __future__ import annotations

import numpy as np
from collections import Counter
from typing import Dict, List, Any, Optional

from app.utils.entropy import shannon_entropy


def compute_source_ip_entropy(flow: Any) -> float:
    """Compute Shannon entropy of source IPs targeting the same destination.

    Low entropy from many diverse sources => likely spoofed flood.
    High entropy => distributed/distinct sources (benign).

    Args:
        flow: FlowState object with accumulated packet data

    Returns:
        Entropy value (higher = more diverse sources)
    """
    # This is computed per-destination, called from the detector
    # with the set of source IPs seen targeting that dst
    return 0.0


def compute_syn_flood_ratio(packets: List[Any]) -> dict:
    """Analyze SYN flood patterns in a flow.

    Computes SYN-to-ACK ratio and SYN packet rate.

    Read-only: only counts flags from observed packets.
    Never sends packets or probes.

    Args:
        packets: List of PacketInfo objects in the flow

    Returns:
        Dict with syn_count, ack_count, syn_to_ack_ratio, syn_rate
    """
    syn_count = 0
    ack_count = 0
    total_count = len(packets)

    for pkt in packets:
        flags = pkt.flags.upper() if pkt.flags else ""
        if "S" in flags and "A" not in flags:
            syn_count += 1
        if "A" in flags:
            ack_count += 1

    syn_to_ack_ratio = float(syn_count) / max(ack_count, 1)
    syn_rate = float(syn_count) / max(total_count, 1)

    return {
        "syn_count": syn_count,
        "ack_count": ack_count,
        "syn_to_ack_ratio": syn_to_ack_ratio,
        "syn_rate": syn_rate,
        "total_packets": total_count,
    }


def compute_udp_amplification_ratio(
    request_packets: List[Any],
    response_packets: List[Any]
) -> dict:
    """Compute UDP amplification ratio.

    response_byte_total / request_byte_total > 20:1 indicates amplification.

    Read-only: only sums packet sizes already observed.
    Never sends requests to amplify traffic.

    Args:
        request_packets: Outbound request packets
        response_packets: Inbound response packets (if observable)

    Returns:
        Dict with request_bytes, response_bytes, amplification_ratio
    """
    req_bytes = sum(p.packet_size for p in request_packets)
    resp_bytes = sum(p.packet_size for p in response_packets)

    ratio = float(resp_bytes) / max(req_bytes, 1)

    return {
        "request_bytes": req_bytes,
        "response_bytes": resp_bytes,
        "amplification_ratio": ratio,
    }


def compute_packet_rate(flow: Any) -> float:
    """Compute packets per second for a flow."""
    dur = flow.duration_seconds()
    if dur <= 0:
        return 0.0
    return flow.packet_count / dur


def compute_byte_rate(flow: Any) -> float:
    """Compute bytes per second for a flow."""
    dur = flow.duration_seconds()
    if dur <= 0:
        return 0.0
    return flow.bytes_transferred / dur


def extract_ddos_features(flow: FlowState) -> dict:
    """Extract all DDoS-related features from a flow.

    Features for ML model + rule-based detection.
    """
    pkt_count = flow.packet_count
    bytes_count = flow.bytes_transferred
    dur = flow.duration_seconds()

    pkt_rate = compute_packet_rate(flow)
    byte_rate = compute_byte_rate(flow)

    # Get destination port count (fan-out)
    dst_port_count = len(flow.dst_ports) if flow.dst_ports else 0

    # Get source port count
    src_port_count = len(flow.src_ports) if flow.src_ports else 0

    # Entropy of destination IPs would need full flow table context
    # For per-flow, we compute limited features

    features = {
        "packet_rate": pkt_rate,
        "byte_rate": byte_rate,
        "duration_seconds": dur,
        "packet_count": pkt_count,
        "bytes_transferred": bytes_count,
        "dst_port_count": dst_port_count,
        "src_port_count": src_port_count,
        "entropy_src_ips": 0.0,  # Would need flow-table-wide data
    }

    # Add rule-based computed features
    syn_info = compute_syn_flood_ratio(flow._packets if hasattr(flow, '_packets') else [])
    features.update({
        "syn_count": syn_info.get("syn_count", 0),
        "syn_to_ack_ratio": syn_info.get("syn_to_ack_ratio", 0.0),
        "syn_rate": syn_info.get("syn_rate", 0.0),
    })

    return features