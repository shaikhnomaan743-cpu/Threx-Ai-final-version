"""Slow-rate application-layer DoS (Slowloris / slow-HTTP) from flow metadata.

PS 26145 category (a) + dataset list ("Slowloris (slow HTTP exhaustion)").
The volumetric DDoS detector keys on HIGH packet rate, so a slow-rate attack
- which exhausts a web server's connection pool by holding many sockets open
while trickling a few bytes - is invisible to it (measured 0% detection).

Passive, one-way signals (no payload, no handshake, no return path):
  per flow   long-lived TCP to a web port, tiny packets, a trickle of
             packets/sec and bytes/sec;
  cross-flow MANY such connections open at the same time to the same
             destination:port (the server-side exhaustion pattern).

The concurrency gate is what separates an attack from ordinary idle
keep-alive or websocket connections: one or two slow sockets are normal,
dozens overlapping on one server are not. Distinct-source count is reported
as evidence, so single-host Slowloris and distributed slow-rate attacks are
both covered.

Reported as threat_class "ddos" (category a), model_version
"slow_rate_dos_v1", so the six PS threat categories are unchanged.
"""
from __future__ import annotations

from collections import defaultdict, deque
from typing import Any, Deque, Dict, Optional, Tuple

from app.alerts.schema import Evidence

WEB_PORTS = frozenset({80, 443, 8000, 8008, 8080, 8443, 8888})


def _duration(flow: Any) -> float:
    d = getattr(flow, "duration_seconds", 0.0)
    d = d() if callable(d) else d
    try:
        d = float(d or 0.0)
    except (TypeError, ValueError):
        d = 0.0
    if d <= 0:
        s, e = getattr(flow, "start_time", 0.0), getattr(flow, "end_time", 0.0)
        try:
            if s not in (None, float("inf")) and e and e > s:
                d = float(e - s)
        except TypeError:
            pass
    return d


class SlowRateDoSDetector:
    def __init__(self, min_duration_s: float = 20.0, max_pkt_rate: float = 2.0,
                 max_avg_pkt_bytes: float = 300.0, max_byte_rate: float = 1000.0,
                 min_concurrent: int = 8, window_s: float = 600.0, max_tracked: int = 5000,
                 min_packets: int = 5, max_silence_s: float = 45.0):
        # min_duration_s is kept below FlowBuilder's 30 s active timeout so
        # live-captured slow connections (exported in 30 s slices) still qualify.
        self.min_duration_s = min_duration_s
        self.max_pkt_rate = max_pkt_rate
        self.max_avg_pkt_bytes = max_avg_pkt_bytes
        self.max_byte_rate = max_byte_rate
        self.min_concurrent = min_concurrent
        self.window_s = window_s
        self.max_tracked = max_tracked
        # Steady-trickle requirement: Slowloris must keep sending (a partial
        # header line every ~10-15 s) or the server times the socket out. An
        # idle HTTP keep-alive connection bursts at the start and then goes
        # silent, so it fails this check even when it is long, slow and small.
        self.min_packets = min_packets
        self.max_silence_s = max_silence_s
        # (dst_ip, dst_port) -> recent slow connections (start, end, src_ip)
        self._slow: Dict[Tuple[str, int], Deque[Tuple[float, float, str]]] = defaultdict(deque)

    def _slow_stats(self, flow: Any) -> Optional[dict]:
        if (getattr(flow, "protocol", "") or "").lower() != "tcp":
            return None
        if getattr(flow, "dst_port", None) not in WEB_PORTS:
            return None
        dur = _duration(flow)
        if dur < self.min_duration_s:
            return None
        pkts = int(getattr(flow, "packet_count", 0) or 0)
        byts = int(getattr(flow, "bytes_transferred", 0) or 0)
        if pkts <= 0:
            return None
        pkt_rate, byte_rate, avg = pkts / dur, byts / dur, byts / pkts
        if pkt_rate > self.max_pkt_rate or avg > self.max_avg_pkt_bytes or byte_rate > self.max_byte_rate:
            return None
        if pkts < self.min_packets:
            return None
        ts = sorted(getattr(flow, "timestamps", None) or [])
        max_gap = 0.0
        if len(ts) >= 2:
            max_gap = max(b - a for a, b in zip(ts, ts[1:]))
            if len(ts) >= pkts:  # series covers every packet: include the tail
                end = getattr(flow, "end_time", 0.0) or 0.0
                if end > ts[-1]:
                    max_gap = max(max_gap, end - ts[-1])
        elif pkts / dur < 1.0 / self.max_silence_s:
            return None
        if max_gap > self.max_silence_s:
            return None
        return {"duration": dur, "pkt_rate": pkt_rate, "byte_rate": byte_rate, "avg_pkt": avg,
                "pkts": pkts, "bytes": byts, "max_silence": max_gap}

    # Multi-core: when True, detect() only runs the per-flow test and leaves
    # the candidate in _last_event for the destination aggregator, which owns
    # the cross-source concurrency count (app/ingest/parallel.py).
    defer_concurrency = False
    _last_event = None

    def detect(self, flow: Any) -> Optional[dict]:
        self._last_event = None
        st = self._slow_stats(flow)
        if st is None:
            return None
        dst, port = getattr(flow, "dst_ip", ""), getattr(flow, "dst_port", 0)
        src = getattr(flow, "src_ip", "")
        start = getattr(flow, "start_time", 0.0) or 0.0
        if start == float("inf"):
            start = 0.0
        ident = (getattr(flow, "src_port", None), getattr(flow, "key", None) or getattr(flow, "flow_id", None))
        if self.defer_concurrency:
            self._last_event = (dst, port, start, src, st, ident)
            return None
        return self.concurrency_event(dst, port, start, src, st, ident)

    def concurrency_event(self, dst: str, port: int, start: float, src: str, st: dict,
                          ident: tuple) -> Optional[dict]:
        """Cross-source half of detect(): same window, gate and result."""
        end = start + st["duration"]
        q = self._slow[(dst, port)]
        q.append((start, end, src))
        cutoff = start - self.window_s
        while q and q[0][1] < cutoff:
            q.popleft()
        while len(q) > self.max_tracked:
            q.popleft()

        overlapping = [(s, e, sip) for (s, e, sip) in q if s <= end and e >= start]
        concurrent = len(overlapping)
        if concurrent < self.min_concurrent:
            return None
        sources = len({sip for _, _, sip in overlapping})

        excess = (concurrent - self.min_concurrent) / max(self.min_concurrent, 1)
        conf = round(min(0.95, 0.62 + 0.33 * min(1.0, excess)), 4)
        return {
            "threat_class": "ddos",
            "severity": "high" if conf > 0.75 else "medium",
            "confidence": conf,
            "source_ip": src, "destination_ip": dst,
            "source_port": ident[0], "destination_port": port,
            "protocol": "tcp",
            "bytes_transferred": st["bytes"], "packet_count": st["pkts"],
            "duration_seconds": round(st["duration"], 3),
            "flow_id": ident[1],
            "evidence": [
                Evidence(feature_name="concurrent_slow_connections", value=concurrent, contribution=0.45,
                         description=f"{concurrent} slow connections open at once to {dst}:{port} "
                                     f"(threshold {self.min_concurrent})"),
                Evidence(feature_name="packet_rate", value=round(st["pkt_rate"], 3), contribution=0.2,
                         description=f"Trickle rate {st['pkt_rate']:.2f} pkt/s over {st['duration']:.0f} s"),
                Evidence(feature_name="avg_packet_size", value=round(st["avg_pkt"], 1), contribution=0.15,
                         description=f"Average packet size {st['avg_pkt']:.0f} B (partial-request sized)"),
                Evidence(feature_name="byte_rate", value=round(st["byte_rate"], 2), contribution=0.1,
                         description=f"Byte rate {st['byte_rate']:.1f} B/s"),
                Evidence(feature_name="distinct_sources", value=sources, contribution=0.1,
                         description=f"{sources} distinct source(s) holding these connections"),
            ],
            "model_version": "slow_rate_dos_v1",
            "raw_features": {"concurrent": concurrent, "distinct_sources": sources, **st},
        }
