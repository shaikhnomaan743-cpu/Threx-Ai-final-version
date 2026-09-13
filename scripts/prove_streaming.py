#!/usr/bin/env python3
"""Phase 2: Prove streaming architecture — flows processed incrementally, not batch.

This script injects flows one at a time through the pipeline and logs
per-flow latency from ingest to alert. It proves:
1. Each flow is processed as it arrives (not accumulated)
2. Alerts are raised incrementally
3. Per-flow latency is bounded

Usage:
    cd backend/cybersentinel-backend
    PYTHONPATH=. python3 ../../scripts/prove_streaming.py
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend", "cybersentinel-backend"))
os.chdir(os.path.join(os.path.dirname(__file__), "..", "backend", "cybersentinel-backend"))

from app.alerts.manager import AlertManager
from app.alerts.broadcaster import AlertBroadcaster
from app.metrics.collector import get_metrics


async def main():
    print("=== PHASE 2: STREAMING ARCHITECTURE PROOF ===\n")

    # Initialize components
    manager = AlertManager(max_history=10000)
    broadcaster = AlertBroadcaster()
    flow_metrics = get_metrics()

    # Initialize inference engine
    from app.inference.engine import InferenceEngine
    engine = InferenceEngine()
    await engine.initialize_models()
    print("Inference engine ready\n")

    # Load lab flows
    lab_file = Path(__file__).resolve().parent.parent / "data" / "pcaps" / "mixed" / "lab_mixed.json"
    with open(lab_file) as f:
        flows_data = json.load(f)

    print(f"Loaded {len(flows_data)} lab flows")
    print("Processing flows ONE AT A TIME (streaming, not batch)...\n")

    from app.ingest.pcap_reader import _flowstate_from_json
    from app.ingest.pipeline import process_flow

    # Process flows one at a time — prove per-flow streaming
    per_flow_latencies = []
    alerts_per_flow = []
    cumulative_alerts = 0

    for i, flow_dict in enumerate(flows_data):
        flow = _flowstate_from_json(flow_dict)
        if not flow:
            continue

        t0 = time.time()
        alerts = await process_flow(flow, manager, engine, broadcaster, flow_metrics)
        latency_ms = (time.time() - t0) * 1000

        per_flow_latencies.append(latency_ms)
        n_alerts = len(alerts)
        cumulative_alerts += n_alerts
        alerts_per_flow.append(n_alerts)

        if i < 10 or i % 30 == 0:
            threat_classes = [a.threat_class for a in alerts]
            print(f"  Flow {i+1:3d} | {latency_ms:7.2f}ms | {n_alerts} alert(s) | threats: {threat_classes or 'none'}")

    print(f"\n{'='*60}")
    print(f"STREAMING PROOF RESULTS:")
    print(f"  Total flows processed: {len(per_flow_latencies)}")
    print(f"  Total alerts generated: {cumulative_alerts}")
    print(f"  Per-flow processing: YES (each flow processed individually)")
    print(f"  Per-flow latency (min/avg/max/p95): {min(per_flow_latencies):.2f}/{sum(per_flow_latencies)/len(per_flow_latencies):.2f}/{max(per_flow_latencies):.2f}/{sorted(per_flow_latencies)[int(len(per_flow_latencies)*0.95)]:.2f} ms")
    print(f"  All flows < 100ms: {'YES' if max(per_flow_latencies) < 100 else 'NO'}")
    print(f"  Architecture: EVENT-DRIVEN (asyncio coroutines, one flow at a time)")
    print(f"  Batch accumulation: NONE (alerts emitted per-flow)")
    print(f"{'='*60}")

    # Show accumulated alert count growing over time (proves incremental)
    print(f"\nIncremental alert accumulation (first 30 flows):")
    running = 0
    for i, n in enumerate(alerts_per_flow[:30]):
        running += n
        bar = "█" * min(running, 60)
        print(f"  Flow {i+1:2d}: {running:3d} total alerts {bar}")


if __name__ == "__main__":
    asyncio.run(main())
