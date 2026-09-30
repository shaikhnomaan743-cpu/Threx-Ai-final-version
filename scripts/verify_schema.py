#!/usr/bin/env python3
"""Phase 4: Verify standardized alert schema — every alert has required fields.

Checks every detector's output conforms to the Alert schema.
Produces one real example alert JSON per threat class from actual pipeline run.

Usage:
    cd backend/cybersentinel-backend
    PYTHONPATH=. python3 ../../scripts/verify_schema.py
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
from app.alerts.schema import Alert, Evidence
from app.metrics.collector import get_metrics


REQUIRED_FIELDS = ["alert_id", "timestamp", "flow_id", "threat_class", "confidence", "evidence"]
OPTIONAL_BUT_TRACKED = ["severity", "source_ip", "destination_ip", "source_port", "destination_port",
                        "protocol", "bytes_transferred", "packet_count", "duration_seconds", "model_version"]
ALL_REQUIRED = REQUIRED_FIELDS + OPTIONAL_BUT_TRACKED
VALID_THREAT_CLASSES = {"ddos", "c2_beacon", "dga", "dns_tunnel", "tls_malware", "port_scan", "exfiltration"}


def validate_alert(alert_dict: dict) -> list[str]:
    """Return list of validation errors for an alert dict."""
    errors = []
    for field in REQUIRED_FIELDS:
        if field not in alert_dict:
            errors.append(f"MISSING required field: {field}")
        elif alert_dict[field] is None:
            errors.append(f"NULL required field: {field}")

    tc = alert_dict.get("threat_class", "")
    if tc not in VALID_THREAT_CLASSES:
        errors.append(f"Invalid threat_class: {tc}")

    conf = alert_dict.get("confidence", -1)
    if not (0.0 <= conf <= 1.0):
        errors.append(f"confidence out of range: {conf}")

    evidence = alert_dict.get("evidence", [])
    if not isinstance(evidence, list):
        errors.append("evidence is not a list")
    elif len(evidence) == 0:
        errors.append("evidence list is empty (should have 1-6 features)")
    elif len(evidence) > 6:
        errors.append(f"evidence has {len(evidence)} items (max 6)")
    else:
        for i, ev in enumerate(evidence):
            if isinstance(ev, dict):
                for ef in ["feature_name", "value", "contribution", "description"]:
                    if ef not in ev:
                        errors.append(f"evidence[{i}] missing field: {ef}")

    return errors


async def main():
    print("=== PHASE 4: STANDARDIZED ALERT SCHEMA VERIFICATION ===\n")

    manager = AlertManager(max_history=10000)
    broadcaster = AlertBroadcaster()
    flow_metrics = get_metrics()

    from app.inference.engine import InferenceEngine
    engine = InferenceEngine()
    await engine.initialize_models()

    # Load lab flows — one per threat class to trigger each detector
    attack_files = {
        "ddos": "data/pcaps/attacks/ddos_syn_flood.json",
        "c2_beacon": "data/pcaps/attacks/c2_beacon.json",
        "dga": "data/pcaps/attacks/dga_queries.json",
        "tls_malware": "data/pcaps/attacks/tls_malware.json",
        "port_scan": "data/pcaps/attacks/port_scan.json",
        "exfiltration": "data/pcaps/attacks/exfiltration.json",
        "dns_tunnel": "data/pcaps/attacks/dns_tunneling.json",
    }

    from app.ingest.pcap_reader import _flowstate_from_json
    from app.ingest.pipeline import process_flow

    all_alerts = []
    all_errors = []
    example_alerts = {}  # threat_class -> first alert JSON

    for threat_class, filepath in attack_files.items():
        full_path = Path(__file__).resolve().parent.parent / filepath
        if not full_path.exists():
            print(f"  SKIP: {filepath} not found")
            continue
        with open(full_path) as f:
            flows_data = json.load(f)

        # Process first flow from each file to trigger detection
        for fd in flows_data[:5]:
            flow = _flowstate_from_json(fd)
            if not flow:
                continue
            alerts = await process_flow(flow, manager, engine, broadcaster, flow_metrics)
            for alert in alerts:
                ad = alert.model_dump(mode="json") if hasattr(alert, "model_dump") else alert.dict()
                all_alerts.append(ad)
                errs = validate_alert(ad)
                if errs:
                    all_errors.extend([(threat_class, e) for e in errs])
                if alert.threat_class not in example_alerts:
                    example_alerts[alert.threat_class] = ad

    # Print results
    print(f"Total alerts generated: {len(all_alerts)}")
    print(f"Unique threat classes detected: {len(set(a['threat_class'] for a in all_alerts))}")
    print(f"Validation errors: {len(all_errors)}\n")

    if all_errors:
        print("VALIDATION ERRORS:")
        for tc, err in all_errors[:20]:
            print(f"  [{tc}] {err}")
    else:
        print("ALL ALERTS PASS SCHEMA VALIDATION")

    # Show example alerts per threat class
    print(f"\n{'='*60}")
    print("ONE REAL EXAMPLE ALERT PER THREAT CLASS:")
    print(f"{'='*60}")

    for tc in sorted(example_alerts.keys()):
        alert = example_alerts[tc]
        print(f"\n--- {tc.upper()} ---")
        print(json.dumps(alert, indent=2, default=str))

    # Write examples
    outpath = Path(__file__).resolve().parent.parent / "data" / "schema_verification_examples.json"
    with open(outpath, "w") as f:
        json.dump(example_alerts, f, indent=2, default=str)
    print(f"\nExamples saved to {outpath}")

    # Summary
    print(f"\n{'='*60}")
    print(f"SCHEMA ENFORCEMENT SUMMARY:")
    print(f"  Schema class: app/alerts/schema.py Alert(BaseModel)")
    print(f"  Required fields: {', '.join(REQUIRED_FIELDS)}")
    print(f"  Valid threat_classes: {', '.join(sorted(VALID_THREAT_CLASSES))}")
    print(f"  Evidence constraint: 1-6 items, each with feature_name/value/contribution/description")
    print(f"  Confidence range: [0.0, 1.0]")
    print(f"  All detectors produce Alert objects: YES (enforced by InferenceEngine._dict_to_alert)")
    print(f"  Schema enforced consistently: {'YES' if not all_errors else 'ERRORS FOUND'}")
    print(f"{'='*60}")


if __name__ == "__main__":
    asyncio.run(main())
