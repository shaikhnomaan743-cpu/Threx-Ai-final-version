#!/usr/bin/env python3
"""Regenerate data/models/evaluation.json from measured artifacts.

The submission deck states that every figure on it regenerates from this
script. That claim was previously false in two ways: the script did not exist,
and `evaluation.json` still carried the pre-audit DGA numbers (train AUC
0.9991 / test AUC 1.0) that the team had already shown to be a length
artifact. The dashboard read that file, so the running app contradicted the
deck.

This script consolidates the real measured outputs into one file:

  backend/data/dga_evaluation.json  -> DGA corpus stats, length-only baseline,
                                       full vs length-ablated CV AUC, confusion
  data/ablation_results.json        -> per-class bidirectional vs unidirectional F1
  data/throughput_measurement.json  -> sustained/burst flows/sec and latency

It does not invent or interpolate. If a source artifact is missing, the
corresponding section is written as {"available": false, "reason": ...} rather
than filled with a plausible value, so a gap is visible instead of papered
over.

Usage:
    python3 scripts/regenerate_evaluation.py            # write
    python3 scripts/regenerate_evaluation.py --check    # verify, exit 1 if stale
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

DGA_EVAL = REPO / "backend" / "data" / "dga_evaluation.json"
ABLATION = REPO / "data" / "ablation_results.json"
THROUGHPUT = REPO / "data" / "throughput_measurement.json"
OUT = REPO / "data" / "models" / "evaluation.json"
# The backend loads its copy from here; keep the two identical.
OUT_MIRROR = REPO / "backend" / "cybersentinel-backend" / "app" / "models" / "artifacts" / "evaluation.json"


def _load(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return None
    except json.JSONDecodeError as e:
        print(f"WARN: {path} is not valid JSON ({e})", file=sys.stderr)
        return None


def _missing(path: Path, how: str) -> dict:
    return {
        "available": False,
        "reason": f"{path.relative_to(REPO)} not found",
        "regenerate_with": how,
    }


def build() -> dict:
    dga = _load(DGA_EVAL)
    abl = _load(ABLATION)
    thr = _load(THROUGHPUT)

    detectors: dict = {}

    if dga:
        detectors["dga"] = {
            "model": "LightGBM (length-ablated)",
            "deployed_features": dga.get("deployed_features", []),
            "cv_auc": dga.get("length_ablated_cv_auc"),
            "cv_sd": dga.get("length_ablated_cv_sd"),
            "test_auc": dga.get("deployed_test_auc"),
            "full_model_cv_auc": dga.get("full_model_cv_auc"),
            # Shipped beside every headline number on purpose: if this is ever
            # close to the model's own AUC, the corpus is length-confounded and
            # the model figure means nothing.
            "length_only_baseline_cv_auc": dga.get("length_only_baseline_cv_auc"),
            "corpus": dga.get("corpus", {}),
            "confusion": dga.get("confusion", {}),
            "trained_at": dga.get("trained_at"),
        }
        c = dga.get("confusion") or {}
        tp, fn, fp, tn = c.get("tp"), c.get("fn"), c.get("fp"), c.get("tn")
        if None not in (tp, fn, fp, tn) and (tp + fn) and (fp + tn):
            detectors["dga"]["tpr"] = round(tp / (tp + fn), 4)
            detectors["dga"]["fpr"] = round(fp / (fp + tn), 4)
    else:
        detectors["dga"] = _missing(
            DGA_EVAL,
            "cd backend/cybersentinel-backend && PYTHONPATH=. python3 scripts/train_dga.py",
        )

    if abl:
        per_mode = abl.get("per_mode", {})
        bi = per_mode.get("bidirectional", {})
        uni = per_mode.get("unidirectional", {})
        sub = per_mode.get("recovered", {})
        classes = sorted(set(bi) | set(uni))
        detectors["unidirectional_ablation"] = {
            "measured_at": abl.get("measured_at"),
            "two_sided_features_removed": abl.get("two_sided_features_removed", []),
            "one_sided_substitutes": abl.get("one_sided_substitutes", []),
            "n_flows": abl.get("n_flows", {}),
            "per_class": {
                cls: {
                    "bidirectional_f1": (bi.get(cls) or {}).get("f1"),
                    "unidirectional_f1": (uni.get(cls) or {}).get("f1"),
                    "with_substitutes_f1": (sub.get(cls) or {}).get("f1"),
                }
                for cls in classes
            },
        }
    else:
        detectors["unidirectional_ablation"] = _missing(
            ABLATION,
            "cd backend/cybersentinel-backend && PYTHONPATH=. python3 scripts/run_ablation.py",
        )

    if thr:
        throughput = {
            "measured_at": thr.get("measured_at"),
            "sustained_flows_per_sec": thr.get("sustained_flows_per_sec"),
            "burst_flows_per_sec": thr.get("burst_flows_per_sec"),
            "p50_latency_ms": thr.get("sustained_p50_latency_ms"),
            "p95_latency_ms": thr.get("sustained_p95_latency_ms"),
            "p99_latency_ms": thr.get("sustained_p99_latency_ms"),
            "n_flows_tested": thr.get("n_flows_tested"),
            "zero_drops": thr.get("zero_drops"),
            "return_path": thr.get("return_path", "NONE"),
            "note": (
                "Throughput and latency are quoted from the SAME run. Hardware "
                "dependent — re-run scripts/measure_throughput.py on the target "
                "machine and quote what it prints."
            ),
        }
    else:
        throughput = _missing(THROUGHPUT, "python3 scripts/measure_throughput.py")

    return {
        "generated_by": "scripts/regenerate_evaluation.py",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "seed": 42,
        "version": "3.0.0",
        "detectors": detectors,
        "throughput": throughput,
        "provenance": (
            "Derived from measured artifacts only. Values are not hand-edited; "
            "edit the source artifact and re-run this script instead."
        ),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if the on-disk file differs from a fresh build")
    args = ap.parse_args()

    payload = build()
    text = json.dumps(payload, indent=2) + "\n"

    if args.check:
        existing = OUT.read_text() if OUT.exists() else ""
        # generated_at always differs; compare everything else.
        def strip(s: str) -> str:
            try:
                d = json.loads(s)
                d.pop("generated_at", None)
                return json.dumps(d, sort_keys=True)
            except Exception:
                return s
        if strip(existing) != strip(text):
            print("STALE: data/models/evaluation.json differs from measured artifacts.")
            print("Run: python3 scripts/regenerate_evaluation.py")
            return 1
        print("OK: evaluation.json matches measured artifacts.")
        return 0

    for dest in (OUT, OUT_MIRROR):
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text)
        print(f"wrote {dest.relative_to(REPO)}")

    d = payload["detectors"].get("dga", {})
    if d.get("available") is not False:
        print(f"  DGA  cv_auc={d.get('cv_auc')}  "
              f"length_only_baseline={d.get('length_only_baseline_cv_auc')}  "
              f"tpr={d.get('tpr')}  fpr={d.get('fpr')}")
    t = payload["throughput"]
    if t.get("available") is not False:
        print(f"  Throughput sustained={t.get('sustained_flows_per_sec')} fps  "
              f"p50={t.get('p50_latency_ms')}ms  p95={t.get('p95_latency_ms')}ms")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
