from __future__ import annotations

import numpy as np
from typing import Dict, List, Any, Optional

from app.utils.ja_hasher import ja3_fingerprint, ja4_fingerprint


def extract_ja3(version: str, ciphers: list, extensions: list,
                curves: list, point_formats: list) -> str:
    """Compute JA3 fingerprint from TLS ClientHello metadata.

    Pure metadata extraction - no payload decryption.

    Args:
        version: TLS version string
        ciphers: List of cipher suite names
        extensions: List of extension names
        curves: List of curve names
        point_formats: List of point format names

    Returns:
        JA3 fingerprint (MD5 hex hash)
    """
    return ja3_fingerprint(version, ciphers, extensions, curves, point_formats)


def extract_ja4(ja3: str, hostname: str, extensions: list,
                rtt: float | None = None) -> str:
    """Compute JA4 fingerprint.

    Extends JA3 with SNI hostname and RTT for better discrimination.

    Read-only: only uses metadata from ClientHello.

    Returns:
        JA4 SHA-256 fingerprint hex string
    """
    return ja4_fingerprint(ja3, hostname, extensions, rtt)


def extract_packet_size_sequence(flow: Any, max_packets: int = 20) -> List[float]:
    """Extract packet size sequence from a flow.

    The first N packet sizes as a feature vector for ML classification.
    Used by TLS malware classifier.

    Read-only: only observes packet sizes already captured.

    Args:
        flow: FlowState object with packet size history
        max_packets: Maximum number of packets to include

    Returns:
        List of packet sizes (up to max_packets)
    """
    sizes = flow.packet_sizes[:max_packets]
    # Pad to max_packets if fewer packets observed
    if len(sizes) < max_packets:
        sizes = sizes + [0.0] * (max_packets - len(sizes))
    return [float(s) for s in sizes]


def extract_tls_features(flow: Any) -> dict:
    """Extract all TLS-related features from a flow.

    Features for malware classification using JA3/JA4 + packet sizes.

    Read-only: only extracts metadata from TLS ClientHello.
    Never attempts decryption.
    """
    # Gather metadata from flow - in a real implementation,
    # this would come from the original packets' TLS ClientHello

    # For now, extract from flow's accumulated data
    # The flow should have stored TLS metadata from packets

    ja3 = flow.ja3 if hasattr(flow, 'ja3') else ""
    ja4 = flow.ja4 if hasattr(flow, 'ja4') else ""
    packet_size_seq = extract_packet_size_sequence(flow)

    # Build JA3 components if not already hashed
    # In practice, the flow would store the raw components
    ciphers = []
    extensions = []
    curves = []
    point_formats = []
    hostname = ""

    # Try to extract from raw features if available
    raw = flow.raw_features if hasattr(flow, 'raw_features') else {}
    ciphers = raw.get("ciphers", [])
    extensions = raw.get("extensions", [])
    curves = raw.get("curves", [])
    point_formats = raw.get("point_formats", [])
    hostname = raw.get("hostname", "")

    # Compute fingerprints
    ja3_hash = ja3_fingerprint(
        raw.get("version", "TLS 1.2"),
        ciphers,
        extensions,
        curves,
        point_formats,
    )

    ja4_hash = ja4_fingerprint(ja3_hash, hostname, extensions)

    features = {
        "ja3": ja3_hash,
        "ja4": ja4_hash,
        "ja3_version": raw.get("version", "TLS 1.2"),
        "packet_size_sequence": packet_size_seq,
        "ciphers_count": len(ciphers),
        "extensions_count": len(extensions),
        "curves_count": len(curves),
        "point_formats_count": len(point_formats),
        "hostname_prefix": hostname[:32] if hostname else "",
    }

    return features