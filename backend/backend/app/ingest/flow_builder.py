from __future__ import annotations

import time
import logging
from collections import defaultdict
from typing import Dict, List, Optional

from app.config import settings

logger = logging.getLogger(__name__)

# Import canonical PacketInfo/FlowState from pcap_reader (with fallback)
try:
    from app.ingest.pcap_reader import PacketInfo, FlowState  # type: ignore
except Exception as e:  # pragma: no cover
    logger.warning(f"[flow_builder] Failed to import from pcap_reader: {e}; defining fallback")
    from app.ingest.pcap_reader import PacketInfo  # type: ignore
    FlowState = None  # type: ignore

try:
    from app.utils.ja_hasher import ip_port_to_5tuple  # type: ignore
except Exception:
    import hashlib

    def ip_port_to_5tuple(src_ip: str, src_port: int | None, dst_ip: str, dst_port: int | None, protocol: str) -> str:  # type: ignore
        sp = src_port if src_port is not None else 0
        dp = dst_port if dst_port is not None else 0
        tuple_str = f"{protocol.lower()}:{src_ip}:{sp}:{dst_ip}:{dp}"
        return hashlib.sha256(tuple_str.encode("utf-8")).hexdigest()[:16]


class FlowBuilder:
    """Groups packets into bidirectional flows keyed by 5-tuple.

    Flows are identified by (src_ip, src_port, dst_ip, dst_port, protocol).
    Maintains flow state with TTL expiry for automatic cleanup.

    Read-only: never sends packets. Only accumulates metadata from
    passive observation.
    """

    def __init__(self, ttl_seconds: int = settings.flow_ttl_seconds):
        self.ttl_seconds = ttl_seconds
        self._flows: Dict[str, FlowState] = {}  # type: ignore
        self._last_cleanup = time.time()

    def _make_key(self, src_ip: str, src_port: int,
                  dst_ip: str, dst_port: int,
                  protocol: str) -> str:
        """Create a 5-tuple flow key."""
        return ip_port_to_5tuple(src_ip, src_port, dst_ip, dst_port, protocol)

    def add_packet(self, pkt_info: PacketInfo) -> str:  # type: ignore
        """Add a packet to the flow builder.

        Returns the flow key for the added packet.
        """
        key = self._make_key(
            pkt_info.src_ip, pkt_info.src_port,
            pkt_info.dst_ip, pkt_info.dst_port,
            pkt_info.protocol
        )

        now = time.time()
        if key not in self._flows:
            self._flows[key] = FlowState(  # type: ignore
                key=key,
                src_ip=pkt_info.src_ip,
                dst_ip=pkt_info.dst_ip,
                protocol=pkt_info.protocol,
                src_port=pkt_info.src_port,
                dst_port=pkt_info.dst_port,
                ttl_expiry=now + self.ttl_seconds,
            )

        flow = self._flows[key]
        flow.add_packet(pkt_info)
        flow.ttl_expiry = now + self.ttl_seconds

        # Periodic TTL cleanup
        if now - self._last_cleanup > 30:
            self._cleanup_expired()
            self._last_cleanup = now

        return key

    def _cleanup_expired(self):
        """Remove flows whose TTL has expired."""
        now = time.time()
        expired = [
            k for k, v in self._flows.items()
            if getattr(v, "ttl_expiry", 0) < now
        ]
        for k in expired:
            del self._flows[k]
        if expired:
            logger.debug(f"[FlowBuilder] Cleaned up {len(expired)} expired flows")

    def get_flows(self) -> Dict[str, FlowState]:  # type: ignore
        """Return all current flow states."""
        return self._flows.copy()

    def get_flow(self, key: str) -> Optional[FlowState]:  # type: ignore
        """Get a specific flow state by key."""
        return self._flows.get(key)

    def get_flow_keys(self) -> List[str]:
        """Return list of active flow keys."""
        return list(self._flows.keys())

    def get_stats(self) -> dict:
        """Get flow statistics."""
        total_flows = len(self._flows)
        total_packets = sum(f.packet_count for f in self._flows.values())
        total_bytes = sum(f.bytes_transferred for f in self._flows.values())
        return {
            "total_flows": total_flows,
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "active_flow_keys": self.get_flow_keys(),
        }

    def count(self) -> int:
        return len(self._flows)


class FlowTable:
    """In-memory flow table with TTL expiry and query operations.

    Stores flow state for the streaming ingest pipeline.
    Used for hot state tracking (recent flows, top talkers, etc.).
    Can be replaced with Redis-backed implementation in production.
    """

    def __init__(self, ttl_seconds: int = settings.flow_ttl_seconds):
        self.ttl_seconds = ttl_seconds
        self._flows: Dict[str, FlowState] = {}  # type: ignore
        self._last_cleanup = time.time()

    def add(self, pkt_info: PacketInfo) -> str:  # type: ignore
        """Add a packet to the flow table. Returns flow key."""
        key = ip_port_to_5tuple(
            pkt_info.src_ip, pkt_info.src_port,
            pkt_info.dst_ip, pkt_info.dst_port,
            pkt_info.protocol
        )

        now = time.time()
        if key not in self._flows:
            self._flows[key] = FlowState(  # type: ignore
                key=key,
                src_ip=pkt_info.src_ip,
                dst_ip=pkt_info.dst_ip,
                protocol=pkt_info.protocol,
                src_port=pkt_info.src_port,
                dst_port=pkt_info.dst_port,
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
        """Remove expired flows."""
        now = time.time()
        expired = [
            k for k, v in self._flows.items()
            if getattr(v, "ttl_expiry", 0) < now
        ]
        for k in expired:
            del self._flows[k]

    def get(self, key: str) -> Optional[dict]:
        """Get flow state as dict by key."""
        flow = self._flows.get(key)
        if flow:
            return flow.to_dict()
        return None

    def get_all(self) -> Dict[str, dict]:
        """Get all flow states as dicts."""
        return {k: v.to_dict() for k, v in self._flows.items()}

    def get_recent_by_src(self, src_ip: str, limit: int = 10) -> List[dict]:
        """Get recent flows from a specific source IP."""
        flows = []
        for flow in self._flows.values():
            if flow.src_ip == src_ip:
                flows.append(flow.to_dict())
        flows.sort(key=lambda f: f["packet_count"], reverse=True)
        return flows[:limit]

    def get_top_talkers(self, n: int = 10) -> List[dict]:
        """Get top N source IPs by packet count."""
        src_stats: dict = defaultdict(int)
        for flow in self._flows.values():
            src_stats[flow.src_ip] += flow.packet_count
        sorted_srcs = sorted(src_stats.items(), key=lambda x: x[1], reverse=True)
        return [
            {"source_ip": ip, "packet_count": count}
            for ip, count in sorted_srcs[:n]
        ]

    def count(self) -> int:
        """Return number of active flows."""
        return len(self._flows)
