import hashlib


def ip_port_to_5tuple(src_ip: str, src_port: int | None,
                      dst_ip: str, dst_port: int | None,
                      protocol: str) -> str:
    """Convert 5-tuple components to a hash string.

    The 5-tuple consists of: source IP, source port, destination IP,
    destination port, and protocol. This is used as a flow identifier.
    """
    # Normalize None ports to 0 for hashing
    sp = src_port if src_port is not None else 0
    dp = dst_port if dst_port is not None else 0

    # Create a deterministic string representation
    tuple_str = f"{protocol.lower()}:{src_ip}:{sp}:{dst_ip}:{dp}"
    return hashlib.sha256(tuple_str.encode("utf-8")).hexdigest()[:16]


def ip_port_tuple(src_ip: str, src_port: int | None,
                  dst_ip: str, dst_port: int | None,
                  protocol: str) -> tuple:
    """Return the 5-tuple as a normalized tuple.

    Returns (protocol, src_ip, src_port, dst_ip, dst_port) with None ports
    replaced by 0 for consistent comparison.
    """
    sp = src_port if src_port is not None else 0
    dp = dst_port if dst_port is not None else 0
    return (protocol.lower(), src_ip, sp, dst_ip, dp)


def five_tuple_hash(packet_5tuple: tuple) -> str:
    """Hash a 5-tuple tuple into a short string ID.

    Args:
        packet_5tuple: (protocol, src_ip, src_port, dst_ip, dst_port)

    Returns:
        SHA-256 hex digest truncated to 16 characters
    """
    tuple_str = f"{packet_5tuple[0]}:{packet_5tuple[1]}:{packet_5tuple[2]}:{packet_5tuple[3]}:{packet_5tuple[4]}"
    return hashlib.sha256(tuple_str.encode("utf-8")).hexdigest()[:16]


def ja3_fingerprint(version: str, ciphers: list, extensions: list,
                     curves: list, point_formats: list) -> str:
    """Compute JA3 fingerprint from TLS ClientHello metadata.

    JA3 is computed by concatenating specific TLS fields and computing
    an MD5 hash. The standard JA3 string format is:
    version:cipher1:cipher2:...:extension1:extension2:...:curve1:...:point_format1:...

    Args:
        version: TLS version string (e.g., "TLS 1.2")
        ciphers: list of cipher suite names
        extensions: list of extension names
        curves: list of curve names
        point_formats: list of point format names

    Returns:
        JA3 fingerprint string (MD5 hex hash)
    """
    parts = []
    # Version
    parts.append(version or " ")
    # Ciphers - sort for determinism
    if ciphers:
        for c in sorted(str(c) for c in ciphers):
            parts.append(c)
    else:
        parts.append(" ")
    # Extensions - sort for determinism
    if extensions:
        for e in sorted(str(e) for e in extensions):
            parts.append(e)
    else:
        parts.append(" ")
    # Curves - sort for determinism
    if curves:
        for crv in sorted(str(crv) for crv in curves):
            parts.append(crv)
    else:
        parts.append(" ")
    # Point formats - sort for determinism
    if point_formats:
        for pf in sorted(str(pf) for pf in point_formats):
            parts.append(pf)
    else:
        parts.append(" ")

    ja3_string = ":".join(parts)
    return hashlib.md5(ja3_string.encode("utf-8")).hexdigest()


def ja4_fingerprint(ja3: str, hostname: str, extensions: list,
                    rtt: float | None = None) -> str:
    """Compute JA4 fingerprint, an extension of JA3.

    JA4 adds the server name indication (hostname) and RTT to the JA3
    fingerprint for more robust malware detection.

    Args:
        ja3: The JA3 fingerprint string
        hostname: Server Name Indication (SNI) hostname
        extensions: list of TLS extension names
        rtt: Round-trip time in seconds (optional)

    Returns:
        JA4 fingerprint string (SHA-256 hex hash)
    """
    parts = [ja3]
    # Hostname (SNI)
    parts.append(hostname or " ")
    # Extensions - sort for determinism
    if extensions:
        for e in sorted(str(e) for e in extensions):
            parts.append(e)
    else:
        parts.append(" ")
    # RTT
    if rtt is not None:
        parts.append(f"{rtt:.3f}")
    else:
        parts.append("0.000")

    ja4_string = ":".join(parts)
    return hashlib.sha256(ja4_string.encode("utf-8")).hexdigest()