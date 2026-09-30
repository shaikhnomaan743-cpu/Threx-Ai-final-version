#!/usr/bin/env python3
"""THREX flow exporter - drives the collector with IPFIX at a set rate.

Stands in for a router/probe exporting flow records across the one-way link.
Builds a pool of labelled lab flows (benign + every attack class) with
scripts/generate_lab_traffic.py, encodes it to IPFIX ONCE, then streams the
pool in a loop at --rate records/sec. Sequence numbers and export time are
re-stamped per datagram so the collector's loss accounting stays exact.

    python scripts/flow_exporter.py --port 4739 --rate 120000 --seconds 60

Prints records sent and the rate actually achieved. It is a separate process
from THREX: the backend never sends anything.
"""
from __future__ import annotations

import argparse
import random
import socket
import struct
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parents[2] / "scripts"))

from app.ingest.flow_records import IPFIXEncoder  # noqa: E402

# Pool mix per 1,000 flows: mostly benign, every PS threat class present.
DEFAULT_MIX = dict(benign=700, ddos=40, slowloris_tool=40, dns_tunnel=30, dga=50,
                   c2_beacon=40, port_scan=20, tls_malware=40, exfiltration=40)
# 'realistic': attacks are a small share of real traffic (3% here). Alert
# handling is a real cost, so the benchmark reports BOTH mixes.
MIXES = {"lab": DEFAULT_MIX,
         "realistic": dict(benign=970, ddos=4, slowloris_tool=4, dns_tunnel=3, dga=5,
                           c2_beacon=4, port_scan=2, tls_malware=4, exfiltration=4)}


def build_pool(n: int, seed: int, mix: str = "lab"):
    import generate_lab_traffic as G
    random.seed(seed)
    gens = dict(benign=G.generate_benign_tcp, ddos=G.generate_ddos_syn_flood,
                slowloris_tool=G.generate_slowloris_tool, dns_tunnel=G.generate_dns_tunneling,
                dga=G.generate_dga_queries, c2_beacon=G.generate_c2_beacon,
                port_scan=G.generate_port_scan, tls_malware=G.generate_tls_malware,
                exfiltration=G.generate_exfiltration)
    m = MIXES[mix]
    total = sum(m.values())
    pool = []
    for label, share in m.items():
        k = max(1, round(n * share / total))
        pool.extend(gens[label](n=k))
    pool.sort(key=lambda r: r.get("start_time", 0.0))
    return pool


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=4739)
    ap.add_argument("--rate", type=float, default=10000, help="records/sec (0 = as fast as possible)")
    ap.add_argument("--seconds", type=float, default=30)
    ap.add_argument("--pool", type=int, default=20000, help="distinct flows in the looped pool")
    ap.add_argument("--mtu", type=int, default=1400, help="max datagram size (use ~8000 on loopback)")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--mix", choices=sorted(MIXES), default="lab",
                    help="lab = 30%% attacks (alert-heavy worst case); realistic = 3%% attacks")
    args = ap.parse_args()

    t = time.time()
    pool = build_pool(args.pool, args.seed, args.mix)
    enc = IPFIXEncoder(mtu=args.mtu)
    msgs = enc.encode(pool)
    counts = [struct.unpack_from(">I", m, 8)[0] for m in msgs]           # cumulative seq
    per_msg = [(counts[i + 1] if i + 1 < len(counts) else enc.seq) - counts[i] for i in range(len(msgs))]
    print(f"pool: {len(pool)} flows -> {len(msgs)} IPFIX datagrams "
          f"(avg {len(pool) / len(msgs):.1f} records, {sum(map(len, msgs)) / len(msgs):.0f} B) "
          f"built in {time.time() - t:.1f}s", flush=True)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 * 1024 * 1024)
    except OSError:
        pass
    dest = (args.host, args.port)
    bufs = [bytearray(m) for m in msgs]
    seq, sent_rec, sent_dg, i = 0, 0, 0, 0
    t0 = time.perf_counter()
    end = t0 + args.seconds
    next_report = t0 + 5
    while True:
        now = time.perf_counter()
        if now >= end:
            break
        # send a burst, then sleep only if ahead of the target rate
        for _ in range(64):
            b = bufs[i]
            struct.pack_into(">II", b, 4, int(time.time()), seq)   # export time, sequence
            sock.sendto(b, dest)
            seq = (seq + per_msg[i]) & 0xFFFFFFFF
            sent_rec += per_msg[i]
            sent_dg += 1
            i = (i + 1) % len(bufs)
            if i == 0:
                # Template must lead the stream again after wrap: message 0 carries it.
                pass
        if args.rate > 0:
            ahead = sent_rec / args.rate - (time.perf_counter() - t0)
            if ahead > 0:
                time.sleep(ahead)
        if now >= next_report:
            el = now - t0
            print(f"  t={el:5.1f}s  sent {sent_rec:,} records  ({sent_rec / el:,.0f}/s)", flush=True)
            next_report += 5
    el = time.perf_counter() - t0
    print(f"DONE: {sent_rec:,} records in {sent_dg:,} datagrams over {el:.1f}s = {sent_rec / el:,.0f} records/s "
          f"(target {args.rate:,.0f}/s)")


if __name__ == "__main__":
    main()
