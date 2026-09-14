#!/usr/bin/env python3
"""Unidirectional resilience ablation.

Every dataset the NIDS literature trains on — CIC-IDS, CTU-13, TON_IoT, the
NetFlow benchmarks in Luay et al. 2026 — is bidirectional. Models built on them
quietly assume both halves of a conversation are visible. A data diode removes
that assumption, and nobody measures what it costs.

Three THREX features are two-sided and would degrade silently on a real
one-way tap:

    syn_to_ack_ratio      (ddos_detector)   needs the ACK
    amplification_ratio   (ddos_detector)   response / request
    byte_ratio_outbound   (exfil_detector)  outbound / inbound

This harness measures that cost and then measures how much is recoverable.

    BIDIRECTIONAL  all features present, as the lab generator emits them
    UNIDIRECTIONAL two-sided features stripped — the honest diode case
    RECOVERED      two-sided features replaced with one-sided substitutes

Usage:
    cd backend/cybersentinel-backend
    PYTHONPATH=. python3 scripts/run_ablation.py
"""
from __future__ import annotations

import asyncio, copy, json, os, sys, time
from pathlib import Path

sys.path.insert(0, os.getcwd())

from app.alerts.manager import AlertManager       # noqa: E402
from app.alerts.broadcaster import AlertBroadcaster  # noqa: E402
from app.metrics.collector import get_metrics     # noqa: E402
from app.inference.engine import InferenceEngine  # noqa: E402
from app.ingest.pcap_reader import _flowstate_from_json  # noqa: E402
from app.ingest.pipeline import process_flow      # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[3]
PCAP_DIR = REPO_ROOT / "data" / "pcaps"
OUT = REPO_ROOT / "data" / "ablation_results.json"

TWO_SIDED = ["syn_to_ack_ratio", "amplification_ratio", "byte_ratio_outbound"]

# labelled file -> ground-truth threat class as emitted by the detectors
FILES = {
    "ddos":         ("attacks/ddos_syn_flood.json", {"ddos", "ddos_syn_flood", "ddos_amplification"}),
    "c2_beacon":    ("attacks/c2_beacon.json",      {"c2_beacon", "beacon"}),
    "dga":          ("attacks/dga_queries.json",    {"dga", "dga_domain"}),
    "dns_tunnel":   ("attacks/dns_tunneling.json",  {"dns_tunnel", "dns_tunneling"}),
    "tls_malware":  ("attacks/tls_malware.json",    {"tls_malware", "malware_tls"}),
    "recon":        ("attacks/port_scan.json",      {"recon", "port_scan", "scanning"}),
    "exfiltration": ("attacks/exfiltration.json",   {"exfiltration", "data_exfiltration"}),
    "benign":       ("benign/benign_tcp.json",      set()),
}

# Amplification-capable services. One-sided detection can still flag a flow
# aimed at these ports at high rate without ever seeing the response.
AMPLIFIER_PORTS = {53, 123, 161, 389, 1900, 11211}


def strip_two_sided(flow: dict) -> dict:
    """Simulate a true one-way tap: the return direction never arrives."""
    f = copy.deepcopy(flow)
    rf = f.get("raw_features") or {}
    for k in TWO_SIDED:
        rf.pop(k, None)
    f["raw_features"] = rf
    return f


def add_one_sided_substitutes(flow: dict) -> dict:
    """Replace each two-sided feature with a substitute computable from the
    outbound direction alone.

        syn_to_ack_ratio    -> packet_rate (packets/sec from one side)
        amplification_ratio -> request rate toward a known amplifier port
        byte_ratio_outbound -> absolute outbound volume + bytes-per-packet
    """
    f = copy.deepcopy(flow)
    rf = f.get("raw_features") or {}
    dur = max(float(f.get("duration_seconds") or 0.0), 1e-6)
    pkts = float(f.get("packet_count") or 0)
    byts = float(f.get("bytes_transferred") or 0)
    dst_port = int(f.get("dst_port") or 0)

    rf["packet_rate_one_sided"] = pkts / dur
    rf["amplifier_request_rate"] = (pkts / dur) if dst_port in AMPLIFIER_PORTS else 0.0
    rf["outbound_bytes_abs"] = byts
    rf["bytes_per_packet"] = byts / max(pkts, 1.0)
    f["raw_features"] = rf
    return f


def one_sided_rules(flow: dict) -> set[str]:
    """Detections reachable from outbound-only evidence.

    Thresholds are calibrated on the benign lab baseline, not tuned per class.
    """
    rf = flow.get("raw_features") or {}
    hits: set[str] = set()
    rate = float(rf.get("packet_rate_one_sided") or 0.0)
    amp_rate = float(rf.get("amplifier_request_rate") or 0.0)
    out_bytes = float(rf.get("outbound_bytes_abs") or 0.0)
    bpp = float(rf.get("bytes_per_packet") or 0.0)

    # SYN flood without the ACK: sustained packet rate from one source.
    if rate > 50.0:
        hits.add("ddos")
    # Amplification without the response: high request rate at an amplifier.
    if amp_rate > 20.0:
        hits.add("ddos")
    # Exfiltration without the inbound side: large one-way volume in big packets.
    if out_bytes > 1_000_000 and bpp > 500.0:
        hits.add("exfiltration")
    return hits


async def run_mode(mode: str, flows_by_class) -> dict:
    """Return per-class {tp, fp, fn} for one ablation mode."""
    stats = {c: {"tp": 0, "fp": 0, "fn": 0} for c in FILES if c != "benign"}

    # A fresh engine per mode. BeaconDetector accumulates per-destination
    # timing history, so reusing one engine lets state from an earlier mode
    # leak into a later one and silently changes its results.
    engine = InferenceEngine()
    await engine.initialize_models()

    for truth, flows in flows_by_class.items():
        for raw in flows:
            work = raw
            if mode in ("unidirectional", "recovered"):
                work = strip_two_sided(work)
            if mode == "recovered":
                work = add_one_sided_substitutes(work)

            fs = _flowstate_from_json(work)
            if fs is None:
                continue

            mgr = AlertManager(max_history=64)
            alerts = await process_flow(fs, mgr, engine, AblationSink(), get_metrics()) or []
            fired = {getattr(a, "threat_class", "") for a in alerts}

            if mode == "recovered":
                fired |= one_sided_rules(work)

            for cls, (_p, accepted) in FILES.items():
                if cls == "benign":
                    continue
                matched = bool(fired & accepted)
                if truth == cls:
                    stats[cls]["tp" if matched else "fn"] += 1
                elif matched and truth == "benign":
                    stats[cls]["fp"] += 1
    return stats


class AblationSink:
    """No-op broadcaster — keeps websocket work out of the measurement."""
    async def broadcast(self, alert):  # noqa: D102
        return None


def prf(s: dict) -> dict:
    tp, fp, fn = s["tp"], s["fp"], s["fn"]
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f1, 4), **s}


async def main() -> None:
    print("=" * 70)
    print("UNIDIRECTIONAL RESILIENCE ABLATION")
    print("=" * 70)

    flows_by_class = {}
    for cls, (rel, _acc) in FILES.items():
        path = PCAP_DIR / rel
        if not path.exists():
            print(f"  [skip] missing {path}")
            continue
        flows_by_class[cls] = json.loads(path.read_text())
        print(f"  loaded {cls:<13} {len(flows_by_class[cls]):>4} flows")

    results = {}
    for mode in ("bidirectional", "unidirectional", "recovered"):
        print(f"\n--- {mode} ---")
        stats = await run_mode(mode, flows_by_class)
        results[mode] = {c: prf(s) for c, s in stats.items()}
        for c, m in results[mode].items():
            print(f"  {c:<13} P {m['precision']:.3f}  R {m['recall']:.3f}  F1 {m['f1']:.3f}")

    print("\n" + "=" * 70)
    print(f"{'threat class':<15}{'bi F1':>9}{'uni F1':>9}{'cost':>9}{'recov F1':>10}{'regained':>10}")
    print("-" * 70)
    chart = []
    for c in results["bidirectional"]:
        b = results["bidirectional"][c]["f1"]
        u = results["unidirectional"][c]["f1"]
        r = results["recovered"][c]["f1"]
        print(f"{c:<15}{b:>9.3f}{u:>9.3f}{u-b:>+9.3f}{r:>10.3f}{r-u:>+10.3f}")
        chart.append({"threat_class": c, "bidirectional_f1": b,
                      "unidirectional_f1": u, "recovered_f1": r,
                      "cost_of_one_way": round(u - b, 4),
                      "regained_by_substitutes": round(r - u, 4)})
    print("=" * 70)

    payload = {
        "measured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "two_sided_features_removed": TWO_SIDED,
        "one_sided_substitutes": ["packet_rate_one_sided", "amplifier_request_rate",
                                  "outbound_bytes_abs", "bytes_per_packet"],
        "n_flows": {c: len(v) for c, v in flows_by_class.items()},
        "per_mode": results,
        "chart": chart,
    }
    OUT.write_text(json.dumps(payload, indent=2))
    print(f"\nResults -> {OUT}")


if __name__ == "__main__":
    asyncio.run(main())
