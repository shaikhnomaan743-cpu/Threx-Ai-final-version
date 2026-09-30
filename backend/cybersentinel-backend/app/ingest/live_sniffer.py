"""Live sniffer – disabled by default (passive mode).

LIVE INGEST requires CYBERSENTINEL_LIVE_INTERFACE env var.
Never sends probes; only passive capture when explicitly enabled.
"""
from __future__ import annotations

import asyncio
import logging
import os
from typing import AsyncGenerator, Optional

from app.config import settings

logger = logging.getLogger(__name__)

# Graceful scapy import
SCAPY_AVAILABLE = False
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP  # type: ignore
    SCAPY_AVAILABLE = True
except Exception as e:  # pragma: no cover
    logger.warning(f"[live_sniffer] scapy not available ({e}); live capture disabled (passive mode)")
    sniff = None  # type: ignore
    IP = TCP = UDP = ICMP = None  # type: ignore

try:
    from app.ingest.pcap_reader import PacketInfo, tcp_dns_or_tls  # type: ignore
except Exception:
    # fallback stub
    from app.ingest.pcap_reader import PacketInfo  # type: ignore

    def tcp_dns_or_tls(pkt):  # type: ignore
        return False


LIVE_DISABLED_MSG = (
    "LIVE INGEST disabled (passive mode). "
    "Set CYBERSENTINEL_LIVE_INTERFACE env var to enable live capture, e.g. "
    "CYBERSENTINEL_LIVE_INTERFACE=eth0. "
    "Current mode: PASSIVE (reading seeded data / JSON flows only)."
)


def is_live_enabled() -> bool:
    """Check if live ingest is explicitly enabled via env var."""
    iface = os.environ.get("CYBERSENTINEL_LIVE_INTERFACE") or getattr(settings, "live_interface", None)
    return bool(iface)


def get_live_interface() -> str | None:
    return os.environ.get("CYBERSENTINEL_LIVE_INTERFACE") or getattr(settings, "live_interface", None)


async def live_sniffer(
    iface: str | None = None,
    count: int | None = None,
) -> AsyncGenerator[PacketInfo, None]:
    """Passive packet sniffer using scapy.sniff().

    Constraints (read-only, no-probe):
    - Never sends packets back toward the traffic source
    - Uses only sniff() with filter, no sr()/send()/sendp()
    - Analyzes metadata only (headers, sizes, timing)

    Disabled by default – requires CYBERSENTINEL_LIVE_INTERFACE.

    Args:
        iface: Network interface name (None for default from env)
        count: Number of packets to capture (None = infinite)

    Yields:
        PacketInfo objects with extracted metadata
    """
    # Check env var gating – PRIMARY requirement
    env_iface = get_live_interface()
    resolved_iface = iface or env_iface

    if not resolved_iface:
        logger.warning(f"[live_sniffer] {LIVE_DISABLED_MSG}")
        # Yield nothing, don't crash – passive mode label
        return
        yield  # make async generator

    if not SCAPY_AVAILABLE or sniff is None:
        logger.error("[live_sniffer] SCAPY not available; cannot start live capture even though interface is set. Staying in passive mode.")
        return
        yield

    # At this point live ingest is explicitly requested – log clearly
    logger.info(f"[live_sniffer] LIVE INGEST enabled on interface={resolved_iface} (passive capture only, no probes)")

    bpf_filter = "ip"
    loop = asyncio.get_event_loop()
    import threading

    result_queue: asyncio.Queue = asyncio.Queue()

    def _sniff_thread():
        """Run sniff in a separate thread."""
        try:
            sniff(  # type: ignore
                iface=resolved_iface,
                filter=bpf_filter,
                count=count,
                prn=lambda pkt: asyncio.run_coroutine_threadsafe(
                    result_queue.put(_extract_packet_info(pkt)), loop
                ) if _extract_packet_info(pkt) is not None else None,
                store=0,
                timeout=settings.flow_ttl_seconds * 2 if count is None else None,
            )
        except PermissionError as e:
            logger.error(f"[live_sniffer] Permission denied on {resolved_iface}: {e} (run with CAP_NET_RAW or sudo)")
        except Exception as e:
            logger.error(f"[live_sniffer thread] Error: {e}")

    thread = threading.Thread(target=_sniff_thread, daemon=True)
    thread.start()

    # Yield packets from queue
    while True:
        # If thread died and queue empty and count limited, break
        if count is not None and not thread.is_alive() and result_queue.empty():
            break
        try:
            pkt_info = await asyncio.wait_for(result_queue.get(), timeout=0.5)
            if pkt_info is not None:
                yield pkt_info
        except asyncio.TimeoutError:
            if count is not None and not thread.is_alive() and result_queue.empty():
                break
            continue
        except asyncio.CancelledError:
            break


def _extract_packet_info(pkt) -> Optional[PacketInfo]:
    """Extract minimal metadata from a Scapy packet passively."""
    if not SCAPY_AVAILABLE or pkt is None:
        return None
    try:
        if not pkt.haslayer(IP):  # type: ignore
            return None
        ip = pkt[IP]  # type: ignore
        proto_map = {1: "icmp", 6: "tcp", 17: "udp"}
        try:
            protocol = proto_map.get(int(ip.proto), "unknown")
        except Exception:
            protocol = "unknown"

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

        ja3 = ""
        dns_query = ""
        dns_qtype = 0

        if tcp_dns_or_tls(pkt):
            try:
                if pkt.haslayer("TLS"):  # type: ignore
                    tls = pkt["TLS"]  # type: ignore
                    if hasattr(tls, 'version'):
                        ja3 = str(tls.version)[:8]
                    if hasattr(tls, 'ciphers') and isinstance(tls.ciphers, list):
                        ja3 = ":".join(str(c) for c in tls.ciphers[:4])
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
            ja3s="",
            dns_query=dns_query,
            dns_qtype=dns_qtype,
            packet_size=len(pkt),
        )
        return pkt_info
    except Exception as e:
        logger.debug(f"[live_sniffer] extract error: {e}")
        return None
