#!/usr/bin/env python3
"""Diode packet-loss degradation study.

WHY THIS EXISTS
---------------
"Unidirectional" is usually read as "no return path". That is only half of it.
A data diode (or an oversubscribed SPAN port) hands the analytics enclave a
*lossy copy* of the link, and because there is no return path there is also no
retransmission request, no ARQ and no flow control. Frames that are dropped on
the way into the enclave are gone permanently.

Every detector in THREX is built on counts and timings derived from the packets
that arrive. So the operational question the literature does not answer is:

    how does each detector degrade as the enclave's copy loses packets?

This harness answers it by resampling each labelled flow at increasing loss
rates and re-running the real detectors at every level.

WHAT IT DOES
------------
For loss in {0, 1, 2, 5, 10, 20}%:
  1. Independently drop each observed packet with probability p.
  2. Recompute the flow's derived features from the surviving packets -
     packet_count, bytes, duration, inter-arrival stats, and the
     direction-sensitive ratios (syn_to_ack_ratio, byte_ratio_outbound).
  3. Run the real InferenceEngine over the degraded flows.
  4. Score per-class precision / recall / F1 against ground truth.

Ground truth comes from the per-class lab files, not the mixed file
(the mixed file carries no labels).

USAGE
    cd backend/cybersentinel-backend
    PYTHONPATH=. python3 ../../scripts/diode_loss_study.py

OUTPUT
    data/diode_loss_study.json   - full results, per detector per loss level
    plus a printed table ready to become a slide.
"""
from __future__ import annotations

import asyncio
import json
import os
import random
import sys
import warnings
from collections import defaultdict
from pathlib import Path

warnings.filterwarnings("ignore")

REPO = Path(__file__).resolve().parent.parent
BACKEND = REPO / "backend" / "cybersentinel-backend"
sys.path.insert(0, str(BACKEND))
os.chdir(BACKEND)

PCAPS = REPO / "data" / "pcaps"

# Ground truth: file -> threat class the detectors are expected to raise.
# "benign" means no alert should fire.
CLASS_FILES = {
    "benign":      PCAPS / "benign" / "benign_tcp.json",
    "ddos":        PCAPS / "attacks" / "ddos_syn_flood.json",
    "c2_beacon":   PCAPS / "attacks" / "c2_beacon.json",
    "recon":       PCAPS / "attacks" / "port_scan.json",
    "tls_malware": PCAPS / "attacks" / "tls_malware.json",
    "exfil":       PCAPS / "attacks" / "exfiltration.json",
    "dns_tunnel":  PCAPS / "attacks" / "dns_tunneling.json",
    "dga":         PCAPS / "attacks" / "dga_queries.json",
}

# Detector output threat_class -> our ground-truth bucket.
ALERT_TO_CLASS = {
    "ddos": "ddos",
    "beacon": "c2_beacon",
    "c2_beacon": "c2_beacon",
    "recon": "recon",
    "scan": "recon",
    "port_scan": "recon",
    "tls_malware": "tls_malware",
    "exfil": "exfil",
    "exfiltration": "exfil",
    "dns_tunnel": "dns_tunnel",
    "dns_tunneling": "dns_tunnel",
    "dga": "dga",
}

LOSS_LEVELS = [0.0, 0.01, 0.02, 0.05, 0.10, 0.20]
TRIALS = 5          # repeat each loss level; loss is stochastic
SEED = 42


# ----------------------------------------------------------------------------
# Loss model
# ----------------------------------------------------------------------------
def apply_loss(flow: dict, p: float, rng: random.Random) -> dict:
    """Drop each observed packet with probability p and recompute features.

    This models the enclave's copy losing frames. Because there is no return
    path, nothing is retransmitted - the derived statistics are simply computed
    over fewer packets, exactly as they would be in a real enclave.
    """
    f = dict(flow)
    f["raw_features"] = dict(flow.get("raw_features") or {})

    if p <= 0:
        return f

    timestamps = list(flow.get("timestamps") or [])
    sizes = list(flow.get("packet_sizes") or [])
    n_obs = max(len(timestamps), len(sizes))

    if n_obs == 0:
        # No per-packet detail; scale the aggregates directly.
        survivors = None
    else:
        survivors = [i for i in range(n_obs) if rng.random() >= p]
        if not survivors:
            survivors = [rng.randrange(n_obs)]  # a flow with zero packets isn't a flow

    original_count = flow.get("packet_count", 0) or 0

    if survivors is None:
        kept_frac = 1.0 - p
        f["packet_count"] = max(1, int(round(original_count * kept_frac)))
        f["bytes_transferred"] = int(round((flow.get("bytes_transferred", 0) or 0) * kept_frac))
    else:
        kept_frac = len(survivors) / n_obs
        f["timestamps"] = [timestamps[i] for i in survivors if i < len(timestamps)]
        f["packet_sizes"] = [sizes[i] for i in survivors if i < len(sizes)]
        f["packet_count"] = max(1, int(round(original_count * kept_frac)))
        f["bytes_transferred"] = int(round((flow.get("bytes_transferred", 0) or 0) * kept_frac))

    ts = f.get("timestamps") or []
    if len(ts) >= 2:
        f["start_time"] = ts[0]
        f["end_time"] = ts[-1]
        f["duration_seconds"] = round(max(ts[-1] - ts[0], 0.001), 4)

    _degrade_raw_features(f["raw_features"], p, kept_frac, rng)
    return f


def _degrade_raw_features(raw: dict, p: float, kept_frac: float, rng: random.Random):
    """Recompute the derived features that depend on packet counts.

    The direction-sensitive ratios are the interesting ones. syn_to_ack_ratio is
    computed as syn_count / max(ack_count, 1). Under loss both counts shrink, so
    the ratio is stable in expectation - until ack_count is driven to zero, at
    which point the max(...,1) guard makes the ratio jump to syn_count. That is
    the failure mode this study is designed to surface.
    """
    if "syn_to_ack_ratio" in raw:
        ratio = raw["syn_to_ack_ratio"] or 0.0
        # Reconstruct plausible counts, drop each side independently, recompute.
        ack_est = 20
        syn_est = max(1, int(round(ratio * ack_est)))
        syn_kept = sum(1 for _ in range(syn_est) if rng.random() >= p)
        ack_kept = sum(1 for _ in range(ack_est) if rng.random() >= p)
        raw["syn_to_ack_ratio"] = round(syn_kept / max(ack_kept, 1), 3)

    if "byte_ratio_outbound" in raw:
        out_ratio = raw["byte_ratio_outbound"] or 0.0
        out_kept = 1.0 - p * rng.uniform(0.5, 1.5)
        in_kept = 1.0 - p * rng.uniform(0.5, 1.5)
        raw["byte_ratio_outbound"] = round(out_ratio * max(out_kept, 0.01) / max(in_kept, 0.01), 3)

    for key in ("txt_query_volume", "unique_dst_ports", "unique_dst_hosts"):
        if key in raw and isinstance(raw[key], (int, float)):
            raw[key] = type(raw[key])(round(raw[key] * kept_frac))

    if "query_frequency" in raw and raw["query_frequency"]:
        raw["query_frequency"] = round(raw["query_frequency"] * kept_frac, 3)

    if "avg_packet_interval" in raw and raw["avg_packet_interval"] and kept_frac > 0:
        # Fewer packets over the same span -> apparent interval stretches.
        raw["avg_packet_interval"] = round(raw["avg_packet_interval"] / kept_frac, 4)


# ----------------------------------------------------------------------------
# Scoring
# ----------------------------------------------------------------------------
def prf(tp: int, fp: int, fn: int):
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return round(precision, 4), round(recall, 4), round(f1, 4)


async def evaluate(engine, labelled, p, rng, from_json):
    """Run every labelled flow at loss p and tally per-class outcomes."""
    tp = defaultdict(int)
    fp = defaultdict(int)
    fn = defaultdict(int)
    benign_false_alarms = 0

    for true_class, raw_flow in labelled:
        degraded = apply_loss(raw_flow, p, rng)
        flow = from_json(degraded)
        if flow is None:
            continue

        alerts = await engine.analyze_flow(flow)
        fired = {ALERT_TO_CLASS.get(getattr(a, "threat_class", ""), None) for a in alerts}
        fired.discard(None)

        if true_class == "benign":
            if fired:
                benign_false_alarms += 1
                for c in fired:
                    fp[c] += 1
            continue

        if true_class in fired:
            tp[true_class] += 1
        else:
            fn[true_class] += 1
        for c in fired - {true_class}:
            fp[c] += 1

    classes = sorted(set(list(tp) + list(fp) + list(fn)))
    per_class = {c: dict(zip(("precision", "recall", "f1"),
                             prf(tp[c], fp[c], fn[c]))) for c in classes}
    macro_f1 = round(sum(v["f1"] for v in per_class.values()) / max(len(per_class), 1), 4)
    return {
        "per_class": per_class,
        "macro_f1": macro_f1,
        "benign_false_alarm_rate": round(benign_false_alarms / 50.0, 4),
    }


# ----------------------------------------------------------------------------
async def main():
    from app.inference.engine import InferenceEngine
    from app.ingest.pcap_reader import _flowstate_from_json

    labelled = []
    for cls, path in CLASS_FILES.items():
        if not path.exists():
            print(f"  WARN missing {path.name}, skipping {cls}")
            continue
        for fl in json.load(open(path)):
            labelled.append((cls, fl))

    print("=" * 74)
    print("DIODE PACKET-LOSS DEGRADATION STUDY")
    print(f"  {len(labelled)} labelled flows across {len(CLASS_FILES)} classes")
    print(f"  loss levels: {[f'{int(l*100)}%' for l in LOSS_LEVELS]}   trials each: {TRIALS}")
    print("=" * 74)

    # NOTE: the beacon detector keeps cross-flow state (_pair_starts, _dst_starts)
    # across calls. A single shared engine reused across every trial/loss-level
    # would leak state between independent runs and silently corrupt exactly the
    # stateful detector this study cares most about. Load models once (slow,
    # stateless) but give every trial a *fresh* detector state.
    engine = InferenceEngine()
    await engine.initialize_models()

    def fresh_beacon_state():
        from app.models.beacon_detector import BeaconDetector
        engine.detectors["beacon"] = BeaconDetector()

    results = {}
    for p in LOSS_LEVELS:
        trials = []
        for t in range(TRIALS):
            fresh_beacon_state()
            rng = random.Random(SEED + t)
            trials.append(await evaluate(engine, labelled, p, rng, _flowstate_from_json))

        macro = sum(x["macro_f1"] for x in trials) / len(trials)
        far = sum(x["benign_false_alarm_rate"] for x in trials) / len(trials)
        agg = defaultdict(lambda: defaultdict(list))
        for x in trials:
            for c, m in x["per_class"].items():
                for k, v in m.items():
                    agg[c][k].append(v)
        per_class = {c: {k: round(sum(vs) / len(vs), 4) for k, vs in m.items()}
                     for c, m in agg.items()}

        results[f"{p:.2f}"] = {
            "loss_pct": round(p * 100, 1),
            "macro_f1": round(macro, 4),
            "benign_false_alarm_rate": round(far, 4),
            "per_class": per_class,
        }
        print(f"  loss {int(p*100):>3d}%   macro-F1 {macro:.4f}   "
              f"benign false-alarm rate {far:.3f}")

    # ---- slide-ready table -------------------------------------------------
    all_classes = sorted({c for r in results.values() for c in r["per_class"]})
    print("\n" + "=" * 74)
    print("PER-DETECTOR F1 vs PACKET LOSS")
    header = f"{'detector':<14}" + "".join(f"{int(p*100):>7d}%" for p in LOSS_LEVELS)
    print(header)
    print("-" * len(header))
    for c in all_classes:
        row = f"{c:<14}"
        for p in LOSS_LEVELS:
            row += f"{results[f'{p:.2f}']['per_class'].get(c, {}).get('f1', 0.0):>8.3f}"
        print(row)
    row = f"{'BENIGN FAR':<14}"
    for p in LOSS_LEVELS:
        row += f"{results[f'{p:.2f}']['benign_false_alarm_rate']:>8.3f}"
    print(row)
    print("=" * 74)

    out = REPO / "data" / "diode_loss_study.json"
    out.write_text(json.dumps({
        "loss_levels": LOSS_LEVELS, "trials": TRIALS, "seed": SEED,
        "n_labelled_flows": len(labelled), "results": results,
    }, indent=2))
    print(f"\nSaved to {out}")


if __name__ == "__main__":
    asyncio.run(main())
