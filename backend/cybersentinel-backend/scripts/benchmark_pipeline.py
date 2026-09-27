#!/usr/bin/env python3
"""THREX end-to-end throughput benchmark (PS 26145 constraint d).

Measures what the slide should claim, with nothing left out:

    flow_exporter.py --IPFIX over UDP--> receiver/splitter --> N detection workers
    (decode -> FlowState -> all detector modules) + dst aggregators --> main process

  * sustained rate   = flows fully through detection per second, over the
                       measurement window (after warm-up), not a peak;
  * latency          = UDP receipt -> detection done, per flow (p50/p95/p99);
  * loss             = exporter sequence gaps (lost before we saw them) +
                       records we could not queue + records never processed.

Usage (repo: backend/cybersentinel-backend; laptop plugged in, Performance mode):
    PYTHONPATH=. python scripts/benchmark_pipeline.py --rate 120000 --seconds 60
    PYTHONPATH=. python scripts/benchmark_pipeline.py --rate 120000 --seconds 60 --mix realistic

Writes data/benchmark_<mix>_<rate>.json at the repo root.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import queue
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
BACKEND = HERE.parent
REPO = BACKEND.parents[1]
sys.path.insert(0, str(BACKEND))
# Alerts are really persisted during the benchmark (same AlertManager +
# background writer as the app), into a throwaway DB, not data/alerts.db.
import tempfile  # noqa: E402
_BENCH_DB = os.path.join(tempfile.mkdtemp(prefix="threx_bench_"), "alerts.db")
os.environ["CYBERSENTINEL_DB_PATH"] = _BENCH_DB


def _cpu_name() -> str:
    try:
        if platform.system() == "Windows":
            out = subprocess.run(["wmic", "cpu", "get", "name"], capture_output=True, text=True, timeout=5).stdout
            lines = [l.strip() for l in out.splitlines() if l.strip() and l.strip() != "Name"]
            if lines:
                return lines[0]
        elif Path("/proc/cpuinfo").exists():
            for line in Path("/proc/cpuinfo").read_text().splitlines():
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return platform.processor() or "unknown"


def pct(xs, p):
    if not xs:
        return None
    xs = sorted(xs)
    k = min(len(xs) - 1, max(0, int(round(p / 100.0 * (len(xs) - 1)))))
    return round(xs[k], 2)


def main():
    cpus = os.cpu_count() or 2
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rate", type=float, default=120000, help="offered load, records/s")
    ap.add_argument("--seconds", type=float, default=60, help="measurement window")
    ap.add_argument("--warmup", type=float, default=8, help="seconds before measuring")
    ap.add_argument("--workers", type=int, default=max(1, cpus - 4),
                    help=f"detection workers (default cpu_count-4 = {max(1, cpus - 4)})")
    ap.add_argument("--aggregators", type=int, default=None, help="dst aggregators (default workers//6)")
    ap.add_argument("--mix", choices=["lab", "realistic"], default="lab")
    ap.add_argument("--port", type=int, default=4739)
    ap.add_argument("--pool", type=int, default=50000)
    ap.add_argument("--mtu", type=int, default=8000, help="datagram size (loopback)")
    ap.add_argument("--batch", type=int, default=1024)
    ap.add_argument("--target", type=float, default=120000)
    ap.add_argument("--p95-limit-ms", type=float, default=250.0)
    args = ap.parse_args()

    import asyncio
    import logging
    logging.disable(logging.WARNING)
    from app.ingest.parallel import ParallelPipeline
    from app.ingest.pipeline import AlertPump
    from app.alerts.manager import AlertManager
    from app.alerts.writer import get_alert_writer
    loop = asyncio.new_event_loop()
    pump = AlertPump(AlertManager(max_history=100_000), broadcaster=None)

    print(f"CPU: {_cpu_name()} | logical CPUs: {cpus} | workers: {args.workers} | mix: {args.mix} "
          f"| offered: {args.rate:,.0f} records/s", flush=True)
    t = time.time()
    pipe = ParallelPipeline("127.0.0.1", args.port, args.workers, batch_size=args.batch,
                            n_aggregators=args.aggregators).start()
    print(f"pipeline ready in {time.time() - t:.1f}s ({len(pipe.agg_qs)} dst aggregators)", flush=True)

    exp = subprocess.Popen(
        [sys.executable, str(HERE / "flow_exporter.py"), "--port", str(args.port), "--rate", str(args.rate),
         "--seconds", str(args.warmup + args.seconds), "--pool", str(args.pool), "--mtu", str(args.mtu),
         "--mix", args.mix],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=str(BACKEND))

    processed = alerts = 0
    lat, per_sec = [], {}
    recv = {}
    t0 = time.monotonic()
    m_start, m_end = t0 + args.warmup, t0 + args.warmup + args.seconds
    processed_at_start = processed_at_end = None
    last_print = t0
    exp_done_at = None

    def drain(block_s):
        nonlocal processed, alerts, recv
        try:
            msg = pipe.out_q.get(timeout=block_s)
        except queue.Empty:
            msg = None
        while msg is not None:
            kind = msg[0]
            if kind == "batch":
                loop.run_until_complete(pump.handle(msg))   # dedup + persist + push, as in the app
                processed += msg[2]
                alerts += len(msg[3])
                s = int(time.monotonic() - t0)
                per_sec[s] = per_sec.get(s, 0) + msg[2]
            elif kind == "stats":
                now = time.monotonic()
                if m_start <= now <= m_end:
                    lat.extend(msg[3])
            try:
                msg = pipe.out_q.get_nowait()
            except queue.Empty:
                msg = None
        try:
            while True:
                _, s = pipe.stats_q.get_nowait()
                recv = s
        except queue.Empty:
            pass

    while True:
        drain(0.05)
        now = time.monotonic()
        if processed_at_start is None and now >= m_start:
            processed_at_start = processed
        if processed_at_end is None and now >= m_end:
            processed_at_end = processed
        if now - last_print >= 5:
            print(f"  t={now - t0:5.1f}s processed {processed:,}  alerts {alerts:,}  "
                  f"recv {recv.get('records', 0):,}  gaps {recv.get('seq_gap_records', 0):,}", flush=True)
            last_print = now
        if exp.poll() is not None and exp_done_at is None:
            exp_done_at = now
        if exp_done_at is not None and processed_at_end is not None:
            # let in-flight work finish, then stop
            if now - exp_done_at > 10 or (recv.get("records", 0) and processed >= recv.get("records", 0)):
                break
    drain(0.5)
    exp_out = exp.stdout.read() if exp.stdout else ""
    pipe.stop()
    get_alert_writer().flush(30)
    persisted = get_alert_writer().written

    sent = None
    for line in exp_out.splitlines():
        if line.startswith("DONE:"):
            sent = int(line.split()[1].replace(",", ""))
    window = processed_at_end - processed_at_start
    rate = window / args.seconds
    received = recv.get("records", 0)
    seq_gaps = recv.get("seq_gap_records", 0)
    not_processed = max(0, received - processed)
    p50, p95, p99 = pct(lat, 50), pct(lat, 95), pct(lat, 99)
    ok = rate >= args.target and (p95 or 1e9) <= args.p95_limit_ms and seq_gaps == 0 and not_processed == 0
    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "hardware": {"cpu": _cpu_name(), "logical_cpus": cpus, "os": platform.platform(),
                     "python": platform.python_version()},
        "config": {"workers": args.workers, "dst_aggregators": len(pipe.agg_qs), "mix": args.mix,
                   "offered_rate": args.rate, "batch": args.batch, "measure_seconds": args.seconds,
                   "warmup_seconds": args.warmup, "transport": "IPFIX over UDP (loopback)",
                   "path": "receiver/splitter -> workers (decode + all detector modules) -> main"},
        "sustained_flows_per_sec": round(rate, 1),
        "latency_ms": {"p50": p50, "p95": p95, "p99": p99, "samples": len(lat)},
        "loss": {"exporter_sent": sent, "received": received, "seq_gap_records": seq_gaps,
                 "receiver_queue_drops_messages": recv.get("queue_drops_messages", 0),
                 "received_not_processed": not_processed},
        "alerts": {"raw_detections": alerts, **pump.stats, "persisted_rows": persisted},
        "target": {"flows_per_sec": args.target, "p95_ms": args.p95_limit_ms, "zero_loss": True, "met": ok},
    }
    out = REPO / "data" / f"benchmark_{args.mix}_{int(args.rate)}.json"
    out.write_text(json.dumps(result, indent=2))
    print("\n=== RESULT ===")
    print(f"sustained end-to-end: {rate:,.0f} flows/s over {args.seconds:.0f}s  "
          f"(offered {args.rate:,.0f}; exporter sent {sent if sent is not None else '?'})")
    print(f"latency p50/p95/p99: {p50} / {p95} / {p99} ms  ({len(lat):,} samples)")
    print(f"loss: seq gaps {seq_gaps:,} | queue drops {recv.get('queue_drops_messages', 0):,} msgs | "
          f"received-not-processed {not_processed:,}")
    print(f"alerts: {pump.stats['alerts_in']:,} detections ({alerts:,} records after worker coalescing) -> "
          f"{pump.stats['alerts_new']:,} unique ({pump.stats['alerts_merged']:,} merged), "
          f"{persisted:,} persisted, {pump.stats['pushed']:,} pushed live "
          f"({pump.stats['push_suppressed']:,} held back by the 200/s cap)")
    print(f"target {args.target:,.0f}/s, p95 <= {args.p95_limit_ms:.0f} ms, 0 loss: "
          f"{'MET' if ok else 'NOT MET'}")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
