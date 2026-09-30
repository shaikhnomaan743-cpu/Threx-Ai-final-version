#!/usr/bin/env python3
"""Detection regression gate for performance work.

Re-runs the end-to-end lab evaluation on EXACTLY the class mix and seeds that
produced data/baseline_detector_evaluation.json, and fails (exit 1) if any
class's detection rate drops, or the benign false-positive rate rises, by more
than the tolerance. Speed changes must pass this before they count.

    PYTHONPATH=. python scripts/check_detection_regression.py [--tol 0.005]
"""
import argparse, json, logging, sys
from pathlib import Path

logging.disable(logging.CRITICAL)
sys.path.insert(0, str(Path(__file__).resolve().parent))
import evaluate_detectors as E  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--tol", type=float, default=0.005, help="allowed drop (fraction), default 0.5 pp")
args = ap.parse_args()

base = json.loads((E.REPO / "data/baseline_detector_evaluation.json").read_text())["pipeline_lab_traffic"]
E.N_PER_CLASS = {"benign": 1000, **{k: v["n_per_seed"] for k, v in base["per_class"].items()}}
E.BENIGN = ("benign",)
E.EXPECTED = {k: v for k, v in E.EXPECTED.items() if k in E.N_PER_CLASS}
E.SEEDS = base["seeds"]
now = E.part_b_pipeline()

ok = True
print(f"{'class':13s} {'baseline':>9s} {'now':>9s}")
for k, v in base["per_class"].items():
    b, n = v["detection_rate"]["mean"], now["per_class"][k]["detection_rate"]["mean"]
    flag = "" if n >= b - args.tol else "   <-- REGRESSION"
    ok &= not flag
    print(f"{k:13s} {b:9.2%} {n:9.2%}{flag}")
b, n = base["benign_false_positive_rate"]["mean"], now["benign_false_positive_rate"]["mean"]
flag = "" if n <= b + args.tol else "   <-- REGRESSION"
ok &= not flag
print(f"{'benign FPR':13s} {b:9.2%} {n:9.2%}{flag}")
print("PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
