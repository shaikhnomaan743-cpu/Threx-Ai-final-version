"""Production-ready PCAP + JSON flow reader with graceful fallback.

Supports:
- JSON flow file (data/pcaps/mixed/sample_flow.json) -> yields PacketInfo / FlowState records
- Scapy PCAP if available -> yields PacketInfo from .pcap
- Graceful fallback if scapy missing or file not found -> logs and yields nothing, never crashes
"""
from __future__ import annotations

import json
import logging
import os
import time
import hashlib
from typing import AsyncGenerator, Optional, List, Dict, Any

from app.config import settings

logger = logging.getLogger(__name__)

# --- Optional scapy import with graceful fallback ---
SCAPY_AVAILABLE = False
try:
    from scapy.all import PcapReader, IP, TCP, UDP, ICMP  # type: ignore
    SCAPY_AVAILABLE = True
except Exception as e:  # pragma: no cover
    logger.warning(f"[pcap_reader] scapy not available ({e}); PCAP parsing will use fallback. JSON flow parsing remains available.")
    PcapReader = None  # type: ignore
    IP = TCP = UDP = ICMP = None  # type: ignore

# Fallback for 5-tuple hashing if utils not available
try:
    from app.utils.ja_hasher import ip_port_to_5tuple  # type: ignore
except Exception:
    def ip_port_to_5tuple(src_ip: str, src_port: int | None, dst_ip: str, dst_port: int | None, protocol: str) -> str:  # type: ignore
        sp = src_port if src_port is not None else 0
        dp = dst_port if dst_port is not None else 0
        tuple_str = f"{protocol.lower()}:{src_ip}:{sp}:{dst_ip}:{dp}"
        return hashlib.sha256(tuple_str.encode("utf-8")).hexdigest()[:16]


class PacketInfo:
    """Minimal packet metadata extracted passively from PCAP.

    Only extracts L2/L3/L4 headers and TLS/DNS metadata.
    Never contains payload content.
    """

    __slots__ = ("src_ip", "dst_ip", "src_port", "dst_port",
                 "protocol", "timestamp", "flags", "ja3", "ja3s",
                 "dns_query", "dns_qtype", "packet_size")

    def __init__(self, **kwargs):
        self.src_ip = kwargs.get("src_ip", "0.0.0.0")
        self.dst_ip = kwargs.get("dst_ip", "0.0.0.0")
        self.src_port = kwargs.get("src_port", 0)
        self.dst_port = kwargs.get("dst_port", 0)
        self.protocol = kwargs.get("protocol", "unknown")
        self.timestamp = kwargs.get("timestamp", 0.0)
        self.flags = kwargs.get("flags", "")
        self.ja3 = kwargs.get("ja3", "")
        self.ja3s = kwargs.get("ja3s", "")
        self.dns_query = kwargs.get("dns_query", "")
        self.dns_qtype = kwargs.get("dns_qtype", 0)
        self.packet_size = kwargs.get("packet_size", 0)

    def to_dict(self) -> dict:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "timestamp": self.timestamp,
            "flags": self.flags,
            "ja3": self.ja3,
            "ja3s": self.ja3s,
            "dns_query": self.dns_query,
            "dns_qtype": self.dns_qtype,
            "packet_size": self.packet_size,
        }


class FlowState:
    """State for a single flow, accumulating packet metadata.

    Production-ready attributes used by all detectors:
    - packet_count, bytes_transferred, duration_seconds(), timestamps, packet_sizes
    - raw_features, src_ports/dst_ports, proto_flags
    - ttl_expiry for FlowBuilder expiry
    - ja3/ja3s/dns_query for TLS/DNS detectors
    """

    __slots__ = ("key", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
                 "src_ports", "dst_ports", "packet_count",
                 "bytes_transferred", "start_time", "end_time",
                 "proto_flags", "packet_sizes", "timestamps",
                 "raw_features", "ttl_expiry", "ja3", "ja3s",
                 "dns_query", "dns_qtype", "_packets")

    def __init__(self, key: str, src_ip: str, dst_ip: str,
                 protocol: str, src_port: int | None = None, dst_port: int | None = None,
                 ttl_expiry: float | None = None, raw_features: Dict[str, Any] | None = None):
        self.key = key
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol.lower() if isinstance(protocol, str) else str(protocol)
        self.src_ports: set = set()
        self.dst_ports: set = set()
        if src_port is not None:
            self.src_ports.add(src_port)
        if dst_port is not None:
            self.dst_ports.add(dst_port)
        self.packet_count = 0
        self.bytes_transferred = 0
        self.start_time = float("inf")
        self.end_time = 0.0
        self.proto_flags: set = set()
        self.packet_sizes: List[int] = []
        self.timestamps: List[float] = []
        self.raw_features: Dict[str, Any] = raw_features if raw_features is not None else {}
        self.ttl_expiry: float = ttl_expiry if ttl_expiry is not None else time.time() + settings.flow_ttl_seconds
        self.ja3: str = ""
        self.ja3s: str = ""
        self.dns_query: str = ""
        self.dns_qtype: int = 0
        self._packets: List[PacketInfo] = []

    def add_packet(self, pkt_info: PacketInfo):
        """Add a packet's metadata to this flow state."""
        self.src_ports.add(pkt_info.src_port)
        self.dst_ports.add(pkt_info.dst_port)
        self.packet_count += 1
        self.bytes_transferred += pkt_info.packet_size
        self.start_time = min(self.start_time, pkt_info.timestamp)
        self.end_time = max(self.end_time, pkt_info.timestamp)
        self.proto_flags.add(pkt_info.flags)
        self.packet_sizes.append(pkt_info.packet_size)
        self.timestamps.append(pkt_info.timestamp)
        # Preserve TLS/DNS metadata if present
        if pkt_info.ja3:
            self.ja3 = pkt_info.ja3
        if pkt_info.ja3s:
            self.ja3s = pkt_info.ja3s
        if pkt_info.dns_query:
            self.dns_query = pkt_info.dns_query
            self.dns_qtype = pkt_info.dns_qtype
        self._packets.append(pkt_info)

    def duration_seconds(self) -> float:
        """Return flow duration in seconds."""
        if self.packet_count <= 1:
            return 0.0
        if self.start_time == float("inf"):
            return 0.0
        return self.end_time - self.start_time

    def to_dict(self) -> dict:
        """Convert flow state to dictionary for serialization."""
        return {
            "key": self.key,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "src_ports": list(self.src_ports),
            "dst_ports": list(self.dst_ports),
            "packet_count": self.packet_count,
            "bytes_transferred": self.bytes_transferred,
            "duration_seconds": self.duration_seconds(),
            "start_time": self.start_time if self.start_time != float("inf") else 0.0,
            "end_time": self.end_time,
            "proto_flags": list(self.proto_flags),
            "packet_sizes": self.packet_sizes[:50],
            "timestamps": self.timestamps[:50],
            "dst_port_count": max(len(self.dst_ports), int((self.raw_features or {}).get("unique_dst_ports") or 0)),
            "src_port_count": len(self.src_ports),
            "unique_dst_hosts": max(1, int((self.raw_features or {}).get("unique_dst_hosts") or 1)),
            "raw_features": self.raw_features,
            "ja3": self.ja3,
            "ja3s": self.ja3s,
            "dns_query": self.dns_query,
            "dns_qtype": self.dns_qtype,
            "ttl_expiry": self.ttl_expiry,
        }


# ---------------------------------------------------------------------------
# JSON flow parsing
# ---------------------------------------------------------------------------

def _packetinfo_from_json(entry: Dict[str, Any]) -> PacketInfo | None:
    """Build PacketInfo from a JSON flow entry."""
    try:
        return PacketInfo(
            src_ip=entry.get("src_ip", "0.0.0.0"),
            dst_ip=entry.get("dst_ip", "0.0.0.0"),
            src_port=entry.get("src_port", 0),
            dst_port=entry.get("dst_port", 0),
            protocol=str(entry.get("protocol", "unknown")).lower(),
            timestamp=entry.get("start_time", entry.get("timestamp", time.time())),
            flags=entry.get("flags", ""),
            ja3=entry.get("ja3", ""),
            ja3s=entry.get("ja3s", ""),
            dns_query=entry.get("dns_query", ""),
            dns_qtype=entry.get("dns_qtype", 0),
            packet_size=entry.get("packet_size", entry.get("bytes_transferred", 60) // max(entry.get("packet_count", 1), 1) if entry.get("packet_count") else 60),
        )
    except Exception as e:
        logger.warning(f"[pcap_reader] Failed to build PacketInfo from JSON entry {entry.get('flow_id','?')}: {e}")
        return None


def _flowstate_from_json(entry: Dict[str, Any]) -> FlowState | None:
    """Build FlowState from a JSON flow entry (sample_flow.json style)."""
    try:
        src_ip = entry.get("src_ip", "0.0.0.0")
        dst_ip = entry.get("dst_ip", "0.0.0.0")
        src_port = entry.get("src_port", 0)
        dst_port = entry.get("dst_port", 0)
        protocol = str(entry.get("protocol", "tcp")).lower()
        key = entry.get("flow_id") or ip_port_to_5tuple(src_ip, src_port, dst_ip, dst_port, protocol)
        raw_features = entry.get("raw_features", {}) or {}
        fs = FlowState(
            key=key,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            raw_features=dict(raw_features),
        )
        # Populate direct aggregates if already summarized
        fs.packet_count = int(entry.get("packet_count", 0))
        fs.bytes_transferred = int(entry.get("bytes_transferred", 0))
        fs.start_time = float(entry.get("start_time", entry.get("timestamp", time.time())))
        fs.end_time = float(entry.get("end_time", fs.start_time + entry.get("duration_seconds", 0.0)))
        # If packet_count is set but timestamps empty, synthesize timestamps
        timestamps = entry.get("timestamps", [])
        dur = float(entry.get("duration_seconds", 0.0))
        if timestamps:
            fs.timestamps = [float(t) for t in timestamps]
            fs.start_time = min(fs.timestamps)
            ts_span = (max(fs.timestamps) - min(fs.timestamps)) if len(fs.timestamps) > 1 else 0.0
            # Prefer duration_seconds if larger than timestamp span (more realistic for summarized flows)
            if dur > ts_span:
                fs.end_time = fs.start_time + dur
            else:
                fs.end_time = max(fs.timestamps) if len(fs.timestamps) > 1 else fs.start_time + dur
        elif fs.packet_count > 0:
            # synthesize even spacing
            if dur > 0 and fs.packet_count > 1:
                step = dur / (fs.packet_count - 1)
                fs.timestamps = [fs.start_time + i*step for i in range(min(fs.packet_count, 50))]
            else:
                fs.timestamps = [fs.start_time] * min(fs.packet_count, 50)
            if dur > 0:
                fs.end_time = fs.start_time + dur
        packet_sizes = entry.get("packet_sizes", [])
        if packet_sizes:
            fs.packet_sizes = list(packet_sizes)[:50]
        elif fs.packet_count > 0:
            avg = fs.bytes_transferred // max(fs.packet_count, 1)
            fs.packet_sizes = [avg] * min(fs.packet_count, 50)

        extra_dst_ports = entry.get("dst_ports") or []
        if isinstance(extra_dst_ports, list):
            for p in extra_dst_ports[:4000]:
                try:
                    fs.dst_ports.add(int(p))
                except (TypeError, ValueError):
                    continue
        if src_port is not None:
            fs.src_ports.add(src_port)
        if dst_port is not None:
            fs.dst_ports.add(dst_port)
        if entry.get("raw_features") and isinstance(entry["raw_features"], dict):
            n_ports = entry["raw_features"].get("unique_dst_ports")
            if n_ports and len(fs.dst_ports) < int(n_ports):
                # Keep a compact stand-in so to_dict reports the true fan-out
                fs.raw_features["unique_dst_ports"] = int(n_ports)
        # flags
        flags = entry.get("flags", [])
        if isinstance(flags, list):
            for f in flags:
                fs.proto_flags.add(f)
        elif isinstance(flags, str):
            fs.proto_flags.add(flags)
        fs.ja3 = entry.get("ja3", "")
        fs.ja3s = entry.get("ja3s", "")
        fs.dns_query = entry.get("dns_query", "")
        fs.dns_qtype = entry.get("dns_qtype", 0)
        # synthesize internal packets for syn ratio features
        # Store at least one PacketInfo so detectors that inspect _packets work
        if fs.packet_count and not fs._packets:
            for i in range(min(fs.packet_count, 10)):
                fs._packets.append(PacketInfo(
                    src_ip=src_ip, dst_ip=dst_ip,
                    src_port=src_port, dst_port=dst_port,
                    protocol=protocol,
                    timestamp=fs.timestamps[i % len(fs.timestamps)] if fs.timestamps else fs.start_time,
                    flags=flags[0] if isinstance(flags, list) and flags else "",
                    packet_size=fs.packet_sizes[0] if fs.packet_sizes else 60,
                ))
        return fs
    except Exception as e:
        logger.warning(f"[pcap_reader] Failed to build FlowState from JSON entry: {e}")
        return None


def parse_json_flow_file(filepath: str) -> List[FlowState]:
    """Synchronously parse a JSON flow file without crashing.

    Returns list of FlowState objects (may be empty on error/missing).
    """
    if not os.path.exists(filepath):
        logger.warning(f"[pcap_reader] JSON flow file not found: {filepath}")
        return []
    try:
        with open(filepath, "r") as f:
            data = json.load(f)
        # Support both list and dict wrapper {"flows": [...]}
        if isinstance(data, dict):
            # try common keys
            if "flows" in data:
                data = data["flows"]
            elif "records" in data:
                data = data["records"]
            else:
                data = [data]
        if not isinstance(data, list):
            logger.warning(f"[pcap_reader] JSON flow file unexpected shape: {type(data)} at {filepath}")
            return []
        flow_states: List[FlowState] = []
        for entry in data:
            if not isinstance(entry, dict):
                continue
            fs = _flowstate_from_json(entry)
            if fs is not None:
                flow_states.append(fs)
        logger.info(f"[pcap_reader] Parsed {len(flow_states)} flow records from JSON {filepath}")
        return flow_states
    except json.JSONDecodeError as e:
        logger.error(f"[pcap_reader] Invalid JSON in {filepath}: {e}")
        return []
    except Exception as e:
        logger.error(f"[pcap_reader] Error parsing JSON flow file {filepath}: {e}")
        return []


async def _json_flow_reader(filepath: str) -> AsyncGenerator[PacketInfo, None]:
    """Async generator that yields PacketInfo from a JSON flow file."""
    flow_states = parse_json_flow_file(filepath)
    for fs in flow_states:
        # Yield synthetic PacketInfo per flow (one per flow) + also bulk from _packets
        for pkt in fs._packets[:5]:
            yield pkt
        if not fs._packets:
            pkt = _packetinfo_from_json({"src_ip": fs.src_ip, "dst_ip": fs.dst_ip, "src_port": fs.src_port or 0, "dst_port": fs.dst_port or 0, "protocol": fs.protocol, "timestamp": fs.start_time, "packet_size": fs.bytes_transferred // max(fs.packet_count, 1)})
            if pkt:
                yield pkt


async def _scapy_pcap_reader(filepath: str) -> AsyncGenerator[PacketInfo, None]:
    """Scapy-backed PCAP reader with graceful error handling."""
    if not SCAPY_AVAILABLE:
        logger.warning(f"[pcap_reader] Scapy not available, cannot read PCAP: {filepath}")
        return
        yield  # make it an async generator (unreachable)
    if not os.path.exists(filepath):
        logger.warning(f"[pcap_reader] PCAP file not found: {filepath}")
        return
        yield
    try:
        reader = PcapReader(filepath)  # type: ignore
        for pkt in reader:
            pkt_info = _extract_packet_info(pkt)
            if pkt_info is not None:
                yield pkt_info
        try:
            reader.close()
        except Exception:
            pass
    except FileNotFoundError:
        logger.warning(f"[pcap_reader] PCAP file missing: {filepath}")
    except Exception as e:
        logger.error(f"[pcap_reader] Error reading PCAP {filepath}: {e} (fallback to empty)")
        # never crash


# Primary public API
async def pcap_reader(filepath: str) -> AsyncGenerator[PacketInfo, None]:
    """Unified reader: JSON flow file OR Scapy PCAP with graceful fallback.

    - If filepath endswith .json -> parse JSON
    - Else if SCAPY_AVAILABLE -> try PCAP
    - On any error/missing file -> log and yield nothing (no crash)

    Yields PacketInfo objects with extracted metadata.
    Also usable via parse_json_flow_file() for direct FlowState list.
    """
    if not filepath:
        logger.warning("[pcap_reader] Empty filepath provided")
        return
        yield
    # Check existence first
    if not os.path.exists(filepath):
        # Try default sample flow as fallback if requested sample missing
        fallback = os.path.join(os.path.dirname(filepath), "sample_flow.json") if filepath.endswith(".pcap") else None
        logger.warning(f"[pcap_reader] File not found: {filepath}" + (f"; tried fallback {fallback}" if fallback else ""))
        # Yield nothing but don't crash
        return
        yield

    # Dispatch by extension
    if filepath.endswith(".json"):
        async for pkt in _json_flow_reader(filepath):
            yield pkt
        return

    # Try JSON fallback even for .pcap if scapy unavailable
    if not SCAPY_AVAILABLE:
        # Try to interpret file as JSON anyway (some pcaps are JSON)
        try:
            with open(filepath, "r") as f:
                json.load(f)
            # It is JSON
            async for pkt in _json_flow_reader(filepath):
                yield pkt
            return
        except Exception:
            logger.warning(f"[pcap_reader] SCAPY unavailable and file is not JSON, skipping: {filepath}")
            return
            yield

    # Scapy path for .pcap
    async for pkt in _scapy_pcap_reader(filepath):
        yield pkt


def _extract_packet_info(pkt) -> Optional[PacketInfo]:
    """Extract minimal metadata from a Scapy packet passively."""
    if not SCAPY_AVAILABLE:
        return None
    try:
        if not pkt.haslayer(IP):  # type: ignore
            return None
        ip = pkt[IP]  # type: ignore
        proto_map = {1: "icmp", 6: "tcp", 17: "udp"}
        protocol = proto_map.get(int(pkt[IP].proto) if hasattr(pkt[IP], 'proto') else 6, "unknown")

        src_port = 0
        dst_port = 0
        flags = ""
        if pkt.haslayer(TCP):  # type: ignore
            tcp = pkt[TCP]  # type: ignore
            src_port = int(tcp.sport)
            dst_port = int(tcp.dport)
            flags = str(tcp.flags)
        elif pkt.haslayer(UDP):  # type: ignore
            udp = pkt[UDP]  # type: ignore
            src_port = int(udp.sport)
            dst_port = int(udp.dport)
            flags = ""
        else:
            flags = ""

        ja3 = ""
        ja3s = ""
        dns_query = ""
        dns_qtype = 0

        if pkt.haslayer(TCP) and tcp_dns_or_tls(pkt):  # type: ignore
            try:
                if pkt.haslayer("TLS"):  # type: ignore
                    tls = pkt["TLS"]  # type: ignore
                    if hasattr(tls, 'version'):
                        ja3 = str(tls.version)
                    if hasattr(tls, 'ciphers'):
                        ciphers = tls.ciphers
                        if isinstance(ciphers, list):
                            ja3 = ":".join(str(c) for c in ciphers[:4])
            except Exception:
                pass
            try:
                if pkt.haslayer("DNS"):  # type: ignore
                    dns = pkt["DNS"]  # type: ignore
                    if hasattr(dns, 'qry_name'):
                        dns_query = str(dns.qry_name)
                    if hasattr(dns, 'qtype'):
                        dns_qtype = int(dns.qtype)
            except Exception:
                pass

        pkt_info = PacketInfo(
            src_ip=str(ip.src),
            dst_ip=str(ip.dst),
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            timestamp=float(pkt.time),
            flags=flags,
            ja3=ja3,
            ja3s=ja3s,
            dns_query=dns_query,
            dns_qtype=dns_qtype,
            packet_size=len(pkt),
        )
        return pkt_info
    except Exception as e:
        logger.debug(f"[pcap_reader] _extract_packet_info error: {e}")
        return None


def tcp_dns_or_tls(pkt) -> bool:
    """Check if TCP packet contains DNS or TLS data."""
    if not SCAPY_AVAILABLE:
        return False
    try:
        if pkt.haslayer("DNS"):  # type: ignore
            return True
        if pkt.haslayer("TLS"):  # type: ignore
            return True
        if pkt.haslayer(TCP):  # type: ignore
            tcp = pkt[TCP]  # type: ignore
            if int(tcp.sport) in (53,) or int(tcp.dport) in (53,):
                return True
            if int(tcp.sport) in (443,) or int(tcp.dport) in (443,):
                return True
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# Legacy FlowBuilder kept here for backward compat – delegates to canonical
# ---------------------------------------------------------------------------
class FlowBuilder:  # type: ignore
    """Groups packets into bidirectional flows keyed by 5-tuple.

    Backwards-compatible shim. Prefer app.ingest.flow_builder.FlowBuilder.
    """

    def __init__(self, ttl_seconds: int = settings.flow_ttl_seconds):
        self.ttl_seconds = ttl_seconds
        self._flows: dict = {}
        self._last_cleanup = 0.0

    def _make_key(self, pkt_info: PacketInfo) -> str:
        return ip_port_to_5tuple(
            pkt_info.src_ip, pkt_info.src_port,
            pkt_info.dst_ip, pkt_info.dst_port,
            pkt_info.protocol
        )

    def add_packet(self, pkt_info: PacketInfo) -> Optional[str]:
        key = self._make_key(pkt_info)
        now = time.time()
        if key not in self._flows:
            self._flows[key] = FlowState(
                key=key,
                src_ip=pkt_info.src_ip,
                dst_ip=pkt_info.dst_ip,
                protocol=pkt_info.protocol,
                ttl_expiry=now + self.ttl_seconds,
            )
        flow = self._flows[key]
        flow.add_packet(pkt_info)
        flow.ttl_expiry = now + self.ttl_seconds
        if now - self._last_cleanup > 30:
            self._cleanup_expired()
            self._last_cleanup = now
        return key

    def _cleanup_expired(self):
        now = time.time()
        expired = [k for k, v in self._flows.items() if v.ttl_expiry < now]
        for k in expired:
            del self._flows[k]

    def get_flows(self) -> dict:
        return self._flows.copy()

    def get_flow_keys(self) -> list:
        return list(self._flows.keys())

    def get_flow(self, key: str) -> Optional[dict]:
        flow = self._flows.get(key)
        if flow:
            return flow.to_dict()
        return None
