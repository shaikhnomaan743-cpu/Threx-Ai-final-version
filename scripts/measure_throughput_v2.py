#!/usr/bin/env python3
"""THREX throughput measurement v2 — finds the REAL ceiling.

The v1 script measured 180 flows pushed through a serial `await` loop, one at
a time. Throughput there is just 1/latency, so it can never report more than
~100 flows/sec no matter how fast the machine is. That is a property of the
harness, not of the pipeline.

This script measures three things instead:

  1. SERIAL       — current behaviour, one flow at a time (the v1 number)
  2. BATCHED      — same models, predictions grouped into batches
  3. SHARDED      — batched, across N worker processes

Run it from the backend directory:

    cd backend/cybersentinel-backend
    OMP_NUM_THREADS=1 PYTHONPATH=. python3 ../../scripts/measure_throughput_v2.py

Writes data/throughput_v2.json and prints a scaling table you can put on a slide.
"""
from __future__ import annotations

import json
import multiprocessing
import os
import platform
import sys
import time
import warnings
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import joblib
import numpy as np

warnings.filterwarnings("ignore")

BACKEND = Path(__file__).resolve().parent.parent / "backend" / "cybersentinel-backend"
sys.path.insert(0, str(BACKEND))
ARTIFACTS = BACKEND / "app" / "models" / "artifacts"

# How many flows each measurement pushes through. Raise for a steadier number.
N_FLOWS = 20_000


def load_models():
    tls = joblib.load(ARTIFACTS / "tls_classifier.joblib")
    ddos = joblib.load(ARTIFACTS / "ddos_detector.joblib")
    tls_model = tls.model if hasattr(tls, "model") else tls
    return tls_model, ddos["model"], ddos["scaler"]


def make_features(n, tls_model, ddos_model, seed=42):
    rng = np.random.default_rng(seed)
    return (
        rng.random((n, tls_model.n_features_in_)),
        rng.random((n, ddos_model.n_features_in_)),
    )


def score_serial(n, tls_model, ddos_model, ddos_scaler, X_tls, X_ddos):
    """One flow at a time — what the pipeline does today."""
    start = time.perf_counter()
    for i in range(n):
        tls_model.predict_proba(X_tls[i:i + 1])
        ddos_model.decision_function(ddos_scaler.transform(X_ddos[i:i + 1]))
    return n / (time.perf_counter() - start)


def score_batched(batch_size, tls_model, ddos_model, ddos_scaler, X_tls, X_ddos):
    """Grouped predictions — same models, same results, one call per batch."""
    n = len(X_tls)
    start = time.perf_counter()
    for i in range(0, n, batch_size):
        tls_model.predict_proba(X_tls[i:i + batch_size])
        ddos_model.decision_function(ddos_scaler.transform(X_ddos[i:i + batch_size]))
    return n / (time.perf_counter() - start)


_WORKER_STATE = {}


def _worker_init():
    _WORKER_STATE["models"] = load_models()


def _worker_run(args):
    share, batch_size = args
    tls_model, ddos_model, ddos_scaler = _WORKER_STATE["models"]
    X_tls, X_ddos = make_features(share, tls_model, ddos_model, seed=os.getpid())
    return score_batched(batch_size, tls_model, ddos_model, ddos_scaler, X_tls, X_ddos)


def score_sharded(n_workers, batch_size, total):
    """Batched, split across worker processes by flow hash."""
    share = total // n_workers
    start = time.perf_counter()
    with ProcessPoolExecutor(max_workers=n_workers, initializer=_worker_init) as pool:
        list(pool.map(_worker_run, [(share, batch_size)] * n_workers))
    return total / (time.perf_counter() - start)


def main():
    cores = multiprocessing.cpu_count()
    print("=" * 66)
    print("THREX THROUGHPUT — REAL CEILING")
    print(f"  host: {platform.processor() or platform.machine()} | {cores} core(s) "
          f"| python {platform.python_version()}")
    print(f"  flows per measurement: {N_FLOWS:,}")
    print("=" * 66)

    tls_model, ddos_model, ddos_scaler = load_models()
    X_tls, X_ddos = make_features(N_FLOWS, tls_model, ddos_model)

    results = {"cores": cores, "n_flows": N_FLOWS, "serial": None,
               "batched": {}, "sharded": {}}

    print("\n[1/3] SERIAL — one flow at a time (this is the v1 number)")
    serial_fps = score_serial(min(2000, N_FLOWS), tls_model, ddos_model,
                              ddos_scaler, X_tls, X_ddos)
    results["serial"] = round(serial_fps, 1)
    print(f"      {serial_fps:>12,.1f} flows/sec")

    print("\n[2/3] BATCHED — same models, predictions grouped")
    for bs in (64, 256, 1024, 4096):
        fps = score_batched(bs, tls_model, ddos_model, ddos_scaler, X_tls, X_ddos)
        results["batched"][bs] = round(fps, 1)
        print(f"      batch={bs:<5,d} {fps:>12,.1f} flows/sec   "
              f"({fps / serial_fps:>6.0f}x serial)")

    print(f"\n[3/3] SHARDED — batch=1024 across worker processes ({cores} core(s) available)")
    if cores < 2:
        print("      SKIPPED — single-core host. Re-run on a multi-core machine;")
        print("      this is the number that shows the design scales.")
    else:
        for w in range(1, cores + 1):
            if w > 1 and w != cores and w % 2:
                continue
            fps = score_sharded(w, 1024, N_FLOWS)
            results["sharded"][w] = round(fps, 1)
            print(f"      {w} worker(s) {fps:>12,.1f} flows/sec")

    best = max([results["serial"], *results["batched"].values(),
                *results["sharded"].values()])
    print("\n" + "=" * 66)
    print(f"  Serial (current pipeline) : {results['serial']:>12,.1f} flows/sec")
    print(f"  Best measured             : {best:>12,.1f} flows/sec")
    print(f"  Headroom left on the table: {best / results['serial']:>12,.0f}x")
    print("=" * 66)

    out = Path(__file__).resolve().parent.parent / "data" / "throughput_v2.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    results["measured_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    out.write_text(json.dumps(results, indent=2))
    print(f"\nSaved to {out}")


if __name__ == "__main__":
    main()
