"""Listen-only UDP collector for NetFlow v5/v9 and IPFIX.

Binds a UDP socket, decodes every datagram with FlowRecordDecoder and enqueues
the resulting flows on the ingest queue. It NEVER sends: no replies, no
template requests, no acknowledgements - UDP flow export is one-way by design,
which is exactly the PS read-only constraint. A live feed cannot be slowed, so
flows are enqueued non-blocking and anything that does not fit is COUNTED as a
drop (never silently lost); exporter sequence numbers additionally reveal
datagrams lost before they reached us (`seq_gap_records`).
"""
from __future__ import annotations

import asyncio
import logging
import socket
import time
from typing import Callable, Optional

from app.ingest.flow_records import FlowRecordDecoder
from app.ingest.pcap_reader import _flowstate_from_json

logger = logging.getLogger(__name__)

_state = {"collector": None}


class FlowCollectorProtocol(asyncio.DatagramProtocol):
    def __init__(self, sink: Callable[[object], bool]):
        self.decoder = FlowRecordDecoder()
        self.sink = sink
        self.transport = None
        self.stats = {"datagrams": 0, "bytes": 0, "flows_enqueued": 0, "flows_dropped": 0,
                      "started_at": time.time()}

    def connection_made(self, transport):
        self.transport = transport
        sock = transport.get_extra_info("socket")
        if sock is not None:
            try:  # a deep kernel buffer absorbs bursts at 100k+ records/s
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32 * 1024 * 1024)
            except OSError:
                pass

    def datagram_received(self, data, addr):
        self.stats["datagrams"] += 1
        self.stats["bytes"] += len(data)
        for rec in self.decoder.decode(data, addr[0] if addr else "?"):
            flow = _flowstate_from_json(rec)
            if flow is None:
                continue
            if self.sink(flow):
                self.stats["flows_enqueued"] += 1
            else:
                self.stats["flows_dropped"] += 1

    def error_received(self, exc):  # e.g. ICMP errors surfaced by the OS
        logger.debug("flow collector socket error: %s", exc)

    def snapshot(self) -> dict:
        s = dict(self.stats)
        s.update(self.decoder.stats)
        s["uptime_s"] = round(time.time() - s.pop("started_at"), 1)
        return s


async def start_flow_collector(host: str, port: int, sink: Callable[[object], bool]):
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: FlowCollectorProtocol(sink), local_addr=(host, port))
    _state["collector"] = protocol
    logger.info("Flow collector listening on udp://%s:%d (NetFlow v5/v9, IPFIX; listen-only)", host, port)
    return transport, protocol


def get_collector_stats() -> Optional[dict]:
    c = _state["collector"]
    return c.snapshot() if c is not None else None
