#!/usr/bin/env python3
"""Reproducible accuracy evidence for every THREX detector.

Read-only: loads the deployed artifacts, never retrains or overwrites them.

Part A - DGA classifier on REAL data (held-out)
    Rebuilds the exact corpus and 80/20 stratified split used by
    scripts/train_dga.py (seed 42) and scores the deployed model on the 20% it
    never saw, twice: as bare labels (how it was trained) and as the real
    full hostnames through the live engine's normalisation.

Part B - Full pipeline, end-to-end, on FRESH lab traffic
    Generates new labelled flows with scripts/generate_lab_traffic.py using
    seeds that were NOT used to build data/pcaps (which uses seed 42), streams
    them through the real InferenceEngine in time order (as live traffic
    arrives), and reports per-class detection rate and benign false-positive
    rate. Repeated over several seeds; mean and spread are reported.

Honest limits (also written into the output JSON):
  - Part B traffic is synthetic, from our own generator. It proves the
    pipeline works end-to-end; it is NOT a public-benchmark accuracy.
  - Lab benign traffic contains no DNS, so Part B cannot measure DGA false
    positives; Part A does that on real benign domains.

Usage (from backend/cybersentinel-backend):
    PYTHONPATH=. python scripts/evaluate_detectors.py
"""
from __future__ import annotations

import asyncio
import contextlib
import csv
import io
import json
import logging
import random
import statistics
import sys
import warnings
from datetime import datetime, timezone
from pathlib import Path

warnings.filterwarnings("ignore")
logging.disable(logging.CRITICAL)

HERE = Path(__file__).resolve().parent
BACKEND = HERE.parent
REPO = BACKEND.parents[1]
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "scripts"))

import numpy as np  # noqa: E402
from sklearn.metrics import (  # noqa: E402
    accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score,
)

OUT = REPO / "data" / "detector_evaluation.json"
SEEDS = [2026, 2027, 2028]
N_PER_CLASS = dict(benign=1000, benign_keepalive=300, ddos=200, slowloris=100, slowloris_tool=150,
                   dns_tunnel=150, dga=300, c2_beacon=200, port_scan=100, tls_malware=150,
                   exfiltration=100)
# benign_keepalive: idle HTTP keep-alive to one busy server - the hard negative
# for slow-rate DoS detection. Counted as benign in every false-positive figure.
BENIGN = ("benign", "benign_keepalive")
# Which alert class counts as a correct detection for each generated label.
EXPECTED = dict(ddos="ddos", slowloris="ddos", slowloris_tool="ddos", dns_tunnel="dns_tunnel", dga="dga",
                c2_beacon="c2_beacon", port_scan="port_scan", tls_malware="tls_malware",
                exfiltration="exfiltration")


def _metrics(y, pred, prob=None):
    tn, fp, fn, tp = confusion_matrix(y, pred).ravel()
    m = dict(n=int(len(y)), accuracy=accuracy_score(y, pred), precision=precision_score(y, pred),
             recall=recall_score(y, pred), f1=f1_score(y, pred), fpr=fp / max(fp + tn, 1),
             tn=int(tn), fp=int(fp), fn=int(fn), tp=int(tp))
    if prob is not None:
        m["auc"] = roc_auc_score(y, prob)
    return {k: (round(float(v), 4) if isinstance(v, float) else v) for k, v in m.items()}


# --------------------------------------------------------------------------- A
def part_a_dga():
    with contextlib.redirect_stdout(io.StringIO()):
        import train_dga as T
        benign, mal = T.load_corpus()
    import joblib
    from sklearn.model_selection import train_test_split
    from app.models.dga_classifier import predict_dga
    from app.inference.engine import _registrable_label

    # Real full hostnames for each label, taken from the same source files.
    host = {}
    with open(T.DGA_CSV, newline="") as fh:
        for r in csv.DictReader(fh):
            label = (r.get("domain") or "").strip().lower()
            if label and label not in host:
                host[label] = (r.get("host") or "").strip().lower()
    seen = 0
    with open(T.TRANCO_CSV, newline="", encoding="utf-8", errors="ignore") as fh:
        for r in csv.reader(fh):
            if len(r) < 2:
                continue
            label = r[1].strip().lower().split(".")[0]
            if label:
                seen += 1
                host.setdefault(label, r[1].strip().lower())
            if seen >= 40000:
                break

    doms = benign + mal
    y = np.array([0] * len(benign) + [1] * len(mal))
    # Same y, same seed, same stratify as train_dga.py -> identical test rows.
    _, te, _, yte = train_test_split(np.arange(len(doms)), y, test_size=0.2,
                                     random_state=T.SEED, stratify=y)
    model = joblib.load(BACKEND / "app/models/artifacts/dga_classifier.joblib")

    def score(strings):
        p = np.array([predict_dga(model, s)["dga_probability"] for s in strings])
        return p, (p > 0.5).astype(int)

    p1, d1 = score([doms[i] for i in te])
    hosts = [host.get(doms[i]) or doms[i] for i in te]
    p2, d2 = score([_registrable_label(h) for h in hosts])
    p3, d3 = score(hosts)

    with open(T.DGA_CSV, newline="") as fh:
        families = sorted({r["subclass"] for r in csv.DictReader(fh) if r.get("class") == "dga"})

    return {
        "data": "REAL: Tranco top-1m + dga_domains.csv (DGArchive-derived)",
        "corpus": {"benign": len(benign), "dga": len(mal), "dga_families": families},
        "split": "80/20 stratified, seed 42 (identical to scripts/train_dga.py)",
        "held_out_bare_labels": _metrics(yte, d1, p1),
        "held_out_real_hostnames_live_path": _metrics(yte, d2, p2),
        "held_out_real_hostnames_if_fqdn_scored_directly": _metrics(yte, d3, p3),
        "caveats": [
            f"Only {len(families)} DGA families in the corpus; dictionary-word DGAs "
            "(e.g. Matsnu, Suppobox) are not represented, so generalisation to them is unproven.",
            "tld_length equals label length for bare labels, so domain length still reaches the "
            "'length-ablated' model through tld_length.",
        ],
    }


# --------------------------------------------------------------------------- B
async def _run_seed(seed, shards: int = 1):
    import generate_lab_traffic as G
    from app.inference.engine import InferenceEngine
    from app.ingest.pcap_reader import _flowstate_from_json
    import app.models.scan_detector as sd
    import app.models.beacon_detector as bd

    # Fresh stateful detectors per seed so runs are independent.
    sd._scan_detector_instance = None
    if hasattr(bd, "_beacon_detector_instance"):
        bd._beacon_detector_instance = None

    random.seed(seed)
    np.random.seed(seed)
    gens = dict(benign=G.generate_benign_tcp, benign_keepalive=G.generate_benign_keepalive,
                ddos=G.generate_ddos_syn_flood,
                slowloris=G.generate_slowloris, slowloris_tool=G.generate_slowloris_tool,
                dns_tunnel=G.generate_dns_tunneling,
                dga=G.generate_dga_queries, c2_beacon=G.generate_c2_beacon,
                port_scan=G.generate_port_scan, tls_malware=G.generate_tls_malware,
                exfiltration=G.generate_exfiltration)
    stream = [(lab, d) for lab, n in N_PER_CLASS.items() for d in gens[lab](n=n)]
    stream.sort(key=lambda x: x[1].get("start_time", 0))  # arrival order

    if shards <= 1:
        eng = InferenceEngine()
        with contextlib.redirect_stdout(io.StringIO()):
            await eng.initialize_models()
        rows = []
        for lab, d in stream:
            f = _flowstate_from_json(d)
            alerts = await eng.analyze_flow(f) if f is not None else []
            rows.append((lab, {str(getattr(a.threat_class, "value", a.threat_class)) for a in alerts}))
    else:
        # Same routing as the multi-core receiver (crc32 of the source
        # address), each shard with its OWN detector state - exactly what
        # separate worker processes have.
        # Destination-level C2 runs in dst aggregators (crc32(dst_ip) % A),
        # fed by every worker, as in app/ingest/parallel.py. Flows arrive in
        # time order in 512-flow slices, each slice split across workers.
        import zlib
        import app.models.ddos_detector as dd
        import app.inference.engine as EM
        from app.ingest.parallel import shard_of
        from app.models.beacon_detector import BeaconDetector
        from app.models.slowloris_detector import SlowRateDoSDetector
        from app.ingest.parallel import dispatch_dst_event, dst_route_key
        n_agg = max(1, shards // 6)
        engines = []
        for _ in range(shards):
            sd._scan_detector_instance = None
            dd._detector_instances.clear()
            e = InferenceEngine()
            with contextlib.redirect_stdout(io.StringIO()):
                await e.initialize_models()
            e.enable_multicore()
            engines.append(e)
        aggs = [(BeaconDetector(), SlowRateDoSDetector()) for _ in range(n_agg)]
        orig_meta = EM._flow_meta
        EM._flow_meta = lambda f: orig_meta(f) + (id(f),)   # simulation-only: map event -> flow
        try:
            classes = [set() for _ in stream]
            for k in range(0, len(stream), 512):
                chunk = range(k, min(k + 512, len(stream)))
                flows = {i: _flowstate_from_json(stream[i][1]) for i in chunk}
                idmap = {id(f): i for i, f in flows.items()}
                per = [[] for _ in range(shards)]
                for i in chunk:
                    per[shard_of(stream[i][1]["src_ip"], shards)].append(i)
                events = []
                for s, idxs in enumerate(per):
                    if not idxs:
                        continue
                    res = await engines[s].analyze_flows_batch([flows[i] for i in idxs])
                    for i, al in zip(idxs, res):
                        classes[i] |= {str(getattr(a.threat_class, "value", a.threat_class)) for a in al}
                    events += [(idmap[m[-1]], ev, hit) for ev, hit, m in engines[s].pending_dst_events]
                    engines[s].pending_dst_events = []
                for i, ev, hit in sorted(events, key=lambda x: x[0]):
                    b, s_ = aggs[zlib.crc32(dst_route_key(ev).encode()) % n_agg]
                    res = dispatch_dst_event(b, s_, ev, hit)
                    if res:
                        classes[i].add(res["threat_class"])
            rows = [(stream[i][0], classes[i]) for i in range(len(stream))]
        finally:
            EM._flow_meta = orig_meta

    per_class = {}
    for lab, want in EXPECTED.items():
        got = [c for l, c in rows if l == lab]
        per_class[lab] = {"n": len(got),
                          "detected_correct_class": sum(want in c for c in got) / len(got),
                          "any_alert": sum(bool(c) for c in got) / len(got)}
    ben = [c for l, c in rows if l in BENIGN]
    per_benign = {b: sum(bool(c) for l, c in rows if l == b) / N_PER_CLASS[b] for b in BENIGN}
    y = np.array([0 if l in BENIGN else 1 for l, _ in rows])
    pred = np.array([1 if c else 0 for _, c in rows])
    return per_class, sum(bool(c) for c in ben) / len(ben), _metrics(y, pred), per_benign


def part_b_pipeline(shards: int = 1):
    runs = [asyncio.run(_run_seed(s, shards)) for s in SEEDS]

    def agg(vals):
        return {"mean": round(statistics.mean(vals), 4),
                "min": round(min(vals), 4), "max": round(max(vals), 4)}

    per_class = {lab: {"n_per_seed": runs[0][0][lab]["n"],
                       "detection_rate": agg([r[0][lab]["detected_correct_class"] for r in runs]),
                       "any_alert_rate": agg([r[0][lab]["any_alert"] for r in runs])}
                 for lab in EXPECTED}
    binary_keys = ["accuracy", "precision", "recall", "f1", "fpr"]
    return {
        "data": "SYNTHETIC lab traffic from scripts/generate_lab_traffic.py (not a public benchmark)",
        "seeds": SEEDS,
        "flows_per_seed": sum(N_PER_CLASS.values()),
        "order": "time-ordered stream through InferenceEngine.analyze_flow (all 7 detectors)",
        "per_class": per_class,
        "benign_false_positive_rate": agg([r[1] for r in runs]),
        "false_positive_rate_by_benign_type": {b: agg([r[3][b] for r in runs]) for b in BENIGN},
        "binary_attack_vs_benign": {k: agg([r[2][k] for r in runs]) for k in binary_keys},
        "caveats": [
            "Generator and detectors were written by the same team; high rates show the pipeline "
            "works end-to-end, not real-world accuracy.",
            "Lab benign traffic has no DNS, so DGA false positives are measured in Part A only.",
            "Generator draws a random source per C2 beacon, which weakens per-host periodicity.",
        ],
    }


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--shards", type=int, default=1,
                    help="simulate the multi-core pipeline: route flows by crc32(src_ip) to N "
                         "independent detector sets (default 1 = single process)")
    ap.add_argument("--skip-dga", action="store_true", help="skip Part A (real-data DGA)")
    args = ap.parse_args()
    global OUT
    if args.shards > 1:
        OUT = OUT.with_name(f"detector_evaluation_shards{args.shards}.json")
    a = {} if args.skip_dga else None
    if a is None:
        print("Part A: DGA on real held-out data ...", flush=True)
        a = part_a_dga()
    print(f"Part B: full pipeline on fresh lab traffic (shards={args.shards}) ...", flush=True)
    b = part_b_pipeline(args.shards)
    b["shards"] = args.shards
    report = {"generated_by": "scripts/evaluate_detectors.py",
              "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "dga_real_data": a, "pipeline_lab_traffic": b}
    OUT.write_text(json.dumps(report, indent=2))

    print("\n=== A. DGA, real held-out data ===" if a else "\n(Part A skipped)")
    for k in (("held_out_bare_labels", "held_out_real_hostnames_live_path",
               "held_out_real_hostnames_if_fqdn_scored_directly") if a else ()):
        m = a[k]
        print(f"  {k:48s} acc {m['accuracy']:.2%}  prec {m['precision']:.2%}  rec {m['recall']:.2%}  "
              f"F1 {m['f1']:.2%}  AUC {m['auc']:.4f}  FPR {m['fpr']:.2%}  (n={m['n']})")
    print(f"\n=== B. Full pipeline, lab traffic, seeds {SEEDS} ===")
    for lab, v in b["per_class"].items():
        r = v["detection_rate"]
        print(f"  {lab:13s} n={v['n_per_seed']:4d}  detected {r['mean']:7.2%}  "
              f"(range {r['min']:.2%}-{r['max']:.2%})")
    fp = b["benign_false_positive_rate"]
    print(f"  benign FPR (all)    {fp['mean']:7.2%}  (range {fp['min']:.2%}-{fp['max']:.2%})")
    for bname, v in b["false_positive_rate_by_benign_type"].items():
        print(f"    FPR {bname:16s} {v['mean']:7.2%}  (range {v['min']:.2%}-{v['max']:.2%})")
    bb = b["binary_attack_vs_benign"]
    print("  binary attack-vs-benign: " + "  ".join(f"{k} {bb[k]['mean']:.2%}" for k in bb))
    print(f"\nWrote {OUT}")


if __name__ == "__main__":
    main()
