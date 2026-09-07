from __future__ import annotations

import numpy as np
from typing import Dict, List, Any, Optional


def compute_outbound_inbound_ratio(
    outbound_bytes: int,
    inbound_bytes: int,
) -> dict:
    """Compute outbound-to-inbound byte ratio.

    Ratio > 10:1 with total volume > 10MB suggests exfiltration.

    Read-only: only uses bytes already observed in flow metadata.
    """
    total = outbound_bytes + inbound_bytes
    ratio = float(outbound_bytes) / max(inbound_bytes, 1)

    return {
        "outbound_bytes": outbound_bytes,
        "inbound_bytes": inbound_bytes,
        "ratio": ratio,
        "total_bytes": total,
        "exfil_likely": ratio > 10.0 and total > 10 * 1024 * 1024,
    }


def compute_session_duration_stats(flow: Any) -> dict:
    """Compute session duration and throughput statistics.

    Long-duration low-throughput flows may indicate slow exfiltration.

    Args:
        flow: FlowState object with timing data

    Returns:
        Dict with duration, throughput, and skew features
    """
    dur = flow.duration_seconds()
    bytes_trans = flow.bytes_transferred

    if dur <= 0:
        return {
            "duration_seconds": 0.0,
            "throughput_bytes_sec": 0.0,
            "outbound_skew": 0.0,
            "is_long_duration": False,
        }

    throughput = bytes_trans / dur

    # Outbound/inbound skew: ratio of flow bytes to expected bidirectional
    # If we can't distinguish direction, use packet count ratio
    # For MVP, assume bytes_trans includes both directions
    # and compute skew from packet direction if available

    features = {
        "duration_seconds": dur,
        "throughput_bytes_sec": throughput,
        "is_long_duration": dur > 60,  # > 1 minute
        "is_high_throughput": throughput > 100_000,  # > 100KB/s
    }

    return features


def compute_byte_skew(
    outbound_bytes: int,
    inbound_bytes: int,
) -> float:
    """Compute byte direction skew.

    Skew = |out - in| / (out + in). Values near 1.0 = heavily one-directional.

    High outbound skew + large total volume = potential exfiltration.
    """
    total = outbound_bytes + inbound_bytes
    if total == 0:
        return 0.0
    skew = float(abs(outbound_bytes - inbound_bytes)) / total
    return skew


def extract_exfil_features(flow: Any) -> dict:
    """Extract all exfiltration features from a flow.

    Features for isolation forest + rule-based detection.

    Read-only: only analyzes observed flow metadata.
    """
    # Get byte counts - in a full implementation, flow would track
    # outbound vs inbound separately
    outbound_bytes = flow.raw_features.get("outbound_bytes", 0) if hasattr(flow, 'raw_features') else 0
    inbound_bytes = flow.raw_features.get("inbound_bytes", 0) if hasattr(flow, 'raw_features') else 0

    ratio_info = compute_outbound_inbound_ratio(outbound_bytes, inbound_bytes)
    duration_info = compute_session_duration_stats(flow)
    skew = compute_byte_skew(outbound_bytes, inbound_bytes)

    features = {
        **ratio_info,
        **duration_info,
        "byte_skew": skew,
        "outbound_bytes": outbound_bytes,
        "inbound_bytes": inbound_bytes,
    }

    # Rule-based exfiltration flag
    features["exfil_alert"] = (
        ratio_info["exfil_likely"]
        or (duration_info["is_long_duration"]
            and duration_info["throughput_bytes_sec"] < 10_000)
    )

    return features