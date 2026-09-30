"""Multi-core flow pipeline (Windows-safe: spawn start method, no SO_REUSEPORT).

    exporter --UDP--> [receiver/splitter process] --raw record bytes, by crc32(src_ip)-->
        [worker 0..W-1: decode -> FlowState -> 7 detector modules (batched)] --alerts+stats-->
        [main process: AlertManager (persisted), dashboard broadcast, metrics]

Why the receiver does NOT decode: fully decoding a record into a flow costs
~19 us, which caps one process near 50k records/s. The receiver only walks
record boundaries and reads the source address (a few us), then forwards the
raw record bytes, re-framed as a small IPFIX/NetFlow message, to the worker
owning that source. Workers do the expensive decode + detection in parallel.

Sharding by source IP keeps every per-source detector exact (port scan,
per-pair C2 series). Destination-level state (Slowloris concurrency, C2
destination fan-in, DDoS source entropy) is kept per worker, i.e. over the
sources that worker owns; scripts/evaluate_detectors.py --shards W measures
the effect on detection instead of assuming there is none.

crc32 is used for shard selection, not hash(): Python's str hash is
randomised per process, so it would route the same source differently in
different processes.

Sequence numbers are accounted in the receiver, which sees every exported
message: `seq_gap_records` = records the exporter sent that never arrived
(loss on the one-way feed, before we ever touch it). `queue_drops` = records
we received but could not hand to a worker because it was saturated. Both are
counted, never silently lost. Nothing here sends a packet anywhere.
"""
from __future__ import annotations

import multiprocessing as mp
import queue
import socket
import struct
import time
import zlib
from typing import Dict, List, Optional, Tuple

VARLEN = 0xFFFF
_SRC_V4, _SRC_V6 = 8, 27


# ------------------------------------------------------------------ splitter
class _Plan:
    """How to find record boundaries and the source address for a template."""
    __slots__ = ("fixed_size", "prefix", "tail", "src_off", "src_len", "raw_template")

    def __init__(self, fields: List[Tuple[int, int, int]], raw_template: bytes):
        self.raw_template = raw_template
        self.src_off, self.src_len = None, 0
        off, prefix_done, self.prefix, self.tail = 0, False, 0, []
        for ie, length, pen in fields:
            if not prefix_done:
                if length == VARLEN:
                    prefix_done = True
                    self.prefix = off
                    self.tail.append(VARLEN)
                    continue
                if not pen and ie in (_SRC_V4, _SRC_V6) and self.src_off is None:
                    self.src_off, self.src_len = off, length
                off += length
            else:
                self.tail.append(length)
        if not prefix_done:
            self.prefix = off
        self.fixed_size = off if not prefix_done else None


def _record_end(data: bytes, pos: int, plan: _Plan, end: int) -> int:
    """Offset just past the record starting at pos (or -1 if truncated)."""
    if plan.fixed_size is not None:
        nxt = pos + plan.fixed_size
        return nxt if nxt <= end else -1
    p = pos + plan.prefix
    for length in plan.tail:
        if p >= end:
            return -1
        if length == VARLEN:
            n = data[p]
            p += 1
            if n == 255:
                if p + 2 > end:
                    return -1
                n = (data[p] << 8) | data[p + 1]
                p += 2
            p += n
        else:
            p += length
    return p if p <= end else -1


class RecordSplitter:
    """Splits NetFlow v5/v9 and IPFIX messages into per-worker messages."""

    def __init__(self, n_workers: int):
        self.n = n_workers
        self.plans: Dict[tuple, _Plan] = {}
        self._next_seq: Dict[tuple, int] = {}
        self._wseq: Dict[tuple, int] = {}     # per (worker, domain) synthetic seq
        self.stats = {"datagrams": 0, "records": 0, "seq_gap_records": 0,
                      "unknown_template_sets": 0, "malformed": 0}

    def _shard(self, src: bytes) -> int:
        return zlib.crc32(src) % self.n if self.n > 1 else 0

    def split(self, data: bytes, exporter: str) -> Tuple[List[bytes], List[Tuple[int, bytes]]]:
        """Returns (broadcast_messages, [(worker, message), ...])."""
        self.stats["datagrams"] += 1
        try:
            v = struct.unpack_from(">H", data)[0]
            if v == 10:
                return self._ipfix(data, exporter)
            if v == 5:
                return [], self._v5(data)
            if v == 9:
                return self._v9(data, exporter)
        except (struct.error, IndexError):
            pass
        self.stats["malformed"] += 1
        return [], []

    # -- IPFIX
    def _ipfix(self, data, exporter):
        _, length, export_t, seq, odid = struct.unpack_from(">HHIII", data)
        end = min(length, len(data))
        dom = (exporter, 10, odid)
        pos, bcast_sets = 16, []
        per_worker: Dict[Tuple[int, int], List[bytes]] = {}
        n_rec = 0
        while pos + 4 <= end:
            set_id, set_len = struct.unpack_from(">HH", data, pos)
            if set_len < 4:
                break
            body, body_end = pos + 4, min(pos + set_len, end)
            if set_id == 2:
                bcast_sets.append(data[pos:pos + set_len])
                self._learn_ipfix_templates(data, body, body_end, dom)
            elif set_id >= 256:
                plan = self.plans.get((dom, set_id))
                if plan is None:
                    self.stats["unknown_template_sets"] += 1
                else:
                    p = body
                    while p < body_end:
                        q = _record_end(data, p, plan, body_end)
                        if q < 0 or q == p:
                            break
                        src = data[p + plan.src_off:p + plan.src_off + plan.src_len] if plan.src_off is not None else b""
                        per_worker.setdefault((self._shard(src), set_id), []).append(data[p:q])
                        n_rec += 1
                        p = q
            pos += set_len
        exp = self._next_seq.get(dom)
        if exp is not None:
            gap = (seq - exp) & 0xFFFFFFFF
            if 0 < gap < 0x7FFFFFFF:
                self.stats["seq_gap_records"] += gap
        self._next_seq[dom] = (seq + n_rec) & 0xFFFFFFFF
        self.stats["records"] += n_rec
        out = []
        if bcast_sets:
            # Templates go to EVERY worker, ahead of this message's data, each
            # stamped with that worker's own running sequence number so worker
            # decoders see a gap-free stream (the receiver is the authority on
            # real loss).
            sets = b"".join(bcast_sets)
            for w in range(self.n):
                s = self._wseq.get((w, dom), 0)
                out.append((w, struct.pack(">HHIII", 10, 16 + len(sets), export_t, s, odid) + sets))
        bcast = []
        for (w, tid), recs in per_worker.items():
            body = b"".join(recs)
            k = (w, dom)
            s = self._wseq.get(k, 0)
            self._wseq[k] = (s + len(recs)) & 0xFFFFFFFF
            dset = struct.pack(">HH", tid, 4 + len(body)) + body
            out.append((w, struct.pack(">HHIII", 10, 16 + len(dset), export_t, s, odid) + dset))
        return bcast, out

    def _learn_ipfix_templates(self, data, pos, end, dom):
        while pos + 4 <= end:
            start = pos
            tid, count = struct.unpack_from(">HH", data, pos)
            pos += 4
            if tid < 256:
                break
            fields = []
            for _ in range(count):
                ie, length = struct.unpack_from(">HH", data, pos)
                pos += 4
                pen = 0
                if ie & 0x8000:
                    ie &= 0x7FFF
                    pen = struct.unpack_from(">I", data, pos)[0]
                    pos += 4
                fields.append((ie, length, pen))
            self.plans[(dom, tid)] = _Plan(fields, data[start:pos])

    # -- NetFlow v5 (fixed 48-byte records, src address at offset 0)
    def _v5(self, data):
        hdr = bytearray(data[:24])
        count = struct.unpack_from(">H", data, 2)[0]
        seq = struct.unpack_from(">I", data, 16)[0]
        dom = ("v5",)
        exp = self._next_seq.get(dom)
        if exp is not None:
            gap = (seq - exp) & 0xFFFFFFFF
            if 0 < gap < 0x7FFFFFFF:
                self.stats["seq_gap_records"] += gap
        self._next_seq[dom] = (seq + count) & 0xFFFFFFFF
        buckets: Dict[int, List[bytes]] = {}
        for i in range(count):
            r = data[24 + 48 * i:72 + 48 * i]
            if len(r) < 48:
                break
            buckets.setdefault(self._shard(r[:4]), []).append(r)
        self.stats["records"] += sum(len(b) for b in buckets.values())
        out = []
        for w, recs in buckets.items():
            h = bytearray(hdr)
            struct.pack_into(">H", h, 2, len(recs))
            out.append((w, bytes(h) + b"".join(recs)))
        return out

    # -- NetFlow v9 (fixed-length templates)
    def _v9(self, data, exporter):
        _, _c, uptime, secs, seq, source_id = struct.unpack_from(">HHIIII", data)
        dom = (exporter, 9, source_id)
        pos, end, bcast_sets = 20, len(data), []
        per_worker: Dict[Tuple[int, int], List[bytes]] = {}
        while pos + 4 <= end:
            set_id, set_len = struct.unpack_from(">HH", data, pos)
            if set_len < 4:
                break
            body, body_end = pos + 4, min(pos + set_len, end)
            if set_id == 0:
                bcast_sets.append(data[pos:pos + set_len])
                p = body
                while p + 4 <= body_end:
                    tid, count = struct.unpack_from(">HH", data, p)
                    fields = [struct.unpack_from(">HH", data, p + 4 + 4 * i) + (0,) for i in range(count)]
                    self.plans[(dom, tid)] = _Plan(fields, b"")
                    p += 4 + 4 * count
            elif set_id >= 256:
                plan = self.plans.get((dom, set_id))
                if plan is None or plan.fixed_size is None:
                    self.stats["unknown_template_sets"] += 1
                else:
                    p = body
                    while p + plan.fixed_size <= body_end:
                        src = data[p + plan.src_off:p + plan.src_off + plan.src_len] if plan.src_off is not None else b""
                        per_worker.setdefault((self._shard(src), set_id), []).append(data[p:p + plan.fixed_size])
                        p += plan.fixed_size
            pos += set_len
        self.stats["records"] += sum(len(v) for v in per_worker.values())
        hdr = lambda s: struct.pack(">HHIIII", 9, 0, uptime, secs, s, source_id)
        bcast = [hdr(seq) + b"".join(bcast_sets)] if bcast_sets else []
        out = []
        for (w, tid), recs in per_worker.items():
            body = b"".join(recs)
            out.append((w, hdr(seq) + struct.pack(">HH", tid, 4 + len(body)) + body))
        return bcast, out


# ------------------------------------------------------------------ processes
def receiver_main(host: str, port: int, worker_qs, stats_q, stop_evt, flush_ms: float = 5.0):
    """Receiver/splitter process. Listen-only UDP socket."""
    n = len(worker_qs)
    sp = RecordSplitter(n)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 64 * 1024 * 1024)
    except OSError:
        pass
    sock.bind((host, port))
    sock.settimeout(0.05)
    pending: List[list] = [[] for _ in range(n)]
    pend_recs = [0] * n
    queue_drops, last_flush, last_stats = 0, time.monotonic(), time.monotonic()
    buf = bytearray(65536)

    def flush(i):
        nonlocal queue_drops
        if not pending[i]:
            return
        try:
            worker_qs[i].put_nowait(pending[i])
        except queue.Full:
            queue_drops += pend_recs[i]
        pending[i], pend_recs[i] = [], 0

    while not stop_evt.is_set():
        try:
            nbytes, addr = sock.recvfrom_into(buf)
            now = time.time()
            data = bytes(buf[:nbytes])
            bcast, parts = sp.split(data, addr[0])
            for m in bcast:                       # templates: every worker, in order
                for i in range(n):
                    pending[i].append((addr[0], m, now))
            for w, m in parts:
                pending[w].append((addr[0], m, now))
                pend_recs[w] += 1
                if len(pending[w]) >= 64:
                    flush(w)
        except socket.timeout:
            pass
        except OSError:
            continue
        t = time.monotonic()
        if (t - last_flush) * 1000.0 >= flush_ms:
            for i in range(n):
                flush(i)
            last_flush = t
        if t - last_stats >= 0.5:
            s = dict(sp.stats)
            s["queue_drops_messages"] = queue_drops
            try:
                stats_q.put_nowait(("receiver", s))
            except queue.Full:
                pass
            last_stats = t
    sock.close()


def worker_main(wid: int, in_q, out_q, stop_evt, batch_size: int = 1024, max_wait_ms: float = 20.0,
                ready_evt=None, agg_qs=None):
    """Detection worker: decode its shard, run all detector modules, report."""
    import asyncio
    import logging
    logging.disable(logging.WARNING)
    from app.ingest.flow_records import FlowRecordDecoder
    from app.ingest.pcap_reader import _flowstate_from_json
    from app.inference.engine import InferenceEngine, backfill_alert

    n_agg = len(agg_qs) if agg_qs else 0
    from app.alerts.manager import AlertManager
    merger = AlertManager()          # used only for its merge rule

    async def run():
        eng = InferenceEngine()
        await eng.initialize_models()
        if n_agg:
            eng.enable_multicore()
        if ready_evt is not None:
            ready_evt.set()
        dec = FlowRecordDecoder()
        flows, lat_src = [], []                 # lat_src: recv_ts per flow
        n_done, last_report, lat_hist = 0, time.monotonic(), []
        batch_started = None
        while not stop_evt.is_set():
            try:
                items = in_q.get(timeout=max_wait_ms / 1000.0)
            except queue.Empty:
                items = None
            if items:
                for exporter, msg, recv_ts in items:
                    for rec in dec.decode(msg, exporter):
                        f = _flowstate_from_json(rec)
                        if f is not None:
                            flows.append(f)
                            lat_src.append(recv_ts)
                if batch_started is None and flows:
                    batch_started = time.monotonic()
            due = flows and (len(flows) >= batch_size or items is None or
                             (time.monotonic() - batch_started) * 1000.0 >= max_wait_ms)
            if due:
                alerts_per_flow = await eng.analyze_flows_batch(flows)
                done = time.time()
                alerts = []
                for f, al in zip(flows, alerts_per_flow):
                    for a in al:
                        alerts.append(backfill_alert(a, getattr(f, "key", None), f.src_ip, f.dst_ip))
                alerts = coalesce_alerts(alerts, merger)
                if n_agg and eng.pending_dst_events:
                    per = [[] for _ in range(n_agg)]
                    for ev in eng.pending_dst_events:
                        per[zlib.crc32(dst_route_key(ev[0]).encode()) % n_agg].append(ev)
                    eng.pending_dst_events = []
                    for i, evs in enumerate(per):
                        if evs:
                            try:
                                agg_qs[i].put(evs, timeout=1.0)
                            except queue.Full:
                                pass
                lat_hist.extend((done - t) * 1000.0 for t in lat_src)
                n_done += len(flows)
                pk = sum(int(getattr(f, "packet_count", 0) or 0) for f in flows)
                by = sum(int(getattr(f, "bytes_transferred", 0) or 0) for f in flows)
                try:
                    out_q.put(("batch", wid, len(flows), alerts, pk, by), timeout=1.0)
                except queue.Full:
                    pass
                flows, lat_src, batch_started = [], [], None
            t = time.monotonic()
            if t - last_report >= 0.5:
                try:
                    out_q.put_nowait(("stats", wid, n_done, lat_hist))
                except queue.Full:
                    pass
                lat_hist, last_report = [], t

    asyncio.run(run())


def coalesce_alerts(alerts, merger) -> list:
    """Merge detections that share AlertManager's dedup key (class, src, dst,
    proto) within one batch, with AlertManager's own merge rule, recording how
    many were folded in (raw_features['_coalesced']) so its per-detection
    counters stay exact. The manager would merge them anyway; doing it here
    means the main process handles one alert per key per batch instead of
    one per detection (a flood yields thousands per second)."""
    out, idx = [], {}
    for a in alerts:
        k = (a.threat_class, a.source_ip.lower(), a.destination_ip.lower(), a.protocol)
        j = idx.get(k)
        if j is None:
            idx[k] = len(out)
            a.raw_features = dict(a.raw_features or {})
            a.raw_features["_coalesced"] = 1
            out.append(a)
        else:
            rep = out[j]
            n = rep.raw_features.get("_coalesced", 1) + 1
            merger._merge_alerts(rep, a)
            rep.raw_features["_coalesced"] = n
    return out


def dst_route_key(ev) -> str:
    """Destination IP an aggregator event belongs to (beacon or slow-rate)."""
    return ev[1] if ev[0] == "slow" else ev[0].split("|", 1)[0]


def dispatch_dst_event(beacon, slow, ev, pair_hit):
    if ev[0] == "slow":
        _, dst, port, start, src, st, ident = ev
        return slow.concurrency_event(dst, port, start, src, st, ident)
    dst_key, start, src, eligible = ev
    return beacon.dst_event(dst_key, start, src, eligible, pair_hit)


def aggregator_main(aid: int, in_q, out_q, stop_evt):
    """Destination-level C2 check over ALL sources of the destinations this
    aggregator owns (crc32(dst_ip) % A). Same logic, thresholds and alert
    conversion as the single-process path."""
    import logging
    logging.disable(logging.WARNING)
    from app.models.beacon_detector import BeaconDetector
    from app.models.slowloris_detector import SlowRateDoSDetector
    from app.inference.engine import InferenceEngine, backfill_alert
    det, slow = BeaconDetector(), SlowRateDoSDetector()
    from app.alerts.manager import AlertManager
    merger = AlertManager()          # used only for its merge rule
    while not stop_evt.is_set():
        try:
            evs = in_q.get(timeout=0.05)
        except queue.Empty:
            continue
        alerts = []
        for ev, pair_hit, meta in evs:
            res = dispatch_dst_event(det, slow, ev, pair_hit)
            if res:
                a = InferenceEngine._dict_to_alert(res)
                if a is not None:
                    InferenceEngine._finalize_alert(a)
                    alerts.append(backfill_alert(a, meta[0], meta[1], meta[2]))
        if alerts:
            alerts = coalesce_alerts(alerts, merger)
            try:
                out_q.put(("batch", f"agg{aid}", 0, alerts, 0, 0), timeout=1.0)
            except queue.Full:
                pass


class ParallelPipeline:
    """Owns the receiver + worker processes; the caller drains `out_q`."""

    def __init__(self, host: str, port: int, n_workers: int, queue_depth: int = 256,
                 batch_size: int = 1024, max_wait_ms: float = 20.0, n_aggregators: Optional[int] = None):
        ctx = mp.get_context("spawn")
        self.ctx, self.host, self.port, self.n = ctx, host, port, max(1, n_workers)
        self.stop_evt = ctx.Event()
        self.worker_qs = [ctx.Queue(maxsize=queue_depth) for _ in range(self.n)]
        # Destination aggregators only matter when there is more than one
        # worker (a single worker already sees every source).
        na = (max(1, self.n // 6) if n_aggregators is None else n_aggregators) if self.n > 1 else 0
        self.agg_qs = [ctx.Queue(maxsize=queue_depth * 4) for _ in range(na)]
        self.out_q = ctx.Queue(maxsize=4096)
        self.stats_q = ctx.Queue(maxsize=64)
        self.ready = [ctx.Event() for _ in range(self.n)]
        self.batch_size, self.max_wait_ms = batch_size, max_wait_ms
        self.procs: List[mp.Process] = []

    def start(self, wait_ready_s: float = 120.0):
        for i, aq in enumerate(self.agg_qs):
            p = self.ctx.Process(target=aggregator_main, name=f"threx-dstagg-{i}", daemon=True,
                                 args=(i, aq, self.out_q, self.stop_evt))
            p.start()
            self.procs.append(p)
        for i in range(self.n):
            p = self.ctx.Process(target=worker_main, name=f"threx-worker-{i}", daemon=True,
                                 args=(i, self.worker_qs[i], self.out_q, self.stop_evt,
                                       self.batch_size, self.max_wait_ms, self.ready[i],
                                       self.agg_qs or None))
            p.start()
            self.procs.append(p)
        deadline = time.monotonic() + wait_ready_s
        for e in self.ready:
            e.wait(max(0.0, deadline - time.monotonic()))
        r = self.ctx.Process(target=receiver_main, name="threx-receiver", daemon=True,
                             args=(self.host, self.port, self.worker_qs, self.stats_q, self.stop_evt))
        r.start()
        self.procs.append(r)
        return self

    def stop(self, timeout: float = 5.0):
        self.stop_evt.set()
        for p in self.procs:
            p.join(timeout)
            if p.is_alive():
                p.terminate()


def shard_of(src_ip: str, n: int) -> int:
    """Same routing as the receiver, for simulations/tests."""
    return zlib.crc32(socket.inet_aton(src_ip)) % n if n > 1 else 0
