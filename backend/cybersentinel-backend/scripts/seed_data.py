#!/usr/bin/env python3
"""Seed database with sample alerts for frontend development.

This script populates the database with sample alerts generated from
sample PCAP data, providing the React frontend with real data to consume
via the REST + WebSocket API.

Usage:
    python scripts/seed_data.py
    # Or: make seed-data
"""

import sys
import os
import json
import time
import uuid
import numpy as np
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cybersentinel_backend.app.config import settings
from cybersentinel_backend.app.alerts.schema import Alert, Evidence
from cybersentinel_backend.app.alerts.manager import AlertManager
from cybersentinel_backend.app.db.session import init_db_session, close_db_session, engine
from cybersentinel_backend.app.db.models import AlertRecord, FlowRecord, MetricSnapshot

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def generate_sample_alerts(n: int = 50) -> List[Dict[str, Any]]:
    """Generate sample alerts with realistic data for frontend demo.

    Creates a mix of different threat types with varying severities
    and confidences to showcase the UI.
    """
    np.random.seed(42)

    threat_types = [
        "ddos",
        "c2_beacon",
        "dga",
        "tls_malware",
        "port_scan",
        "exfiltration",
    ]

    severity_map = {
        "ddos": ["high", "critical"],
        "c2_beacon": ["high", "medium"],
        "dga": ["medium", "high"],
        "tls_malware": ["high", "critical"],
        "port_scan": ["medium", "low"],
        "exfiltration": ["high", "critical", "medium"],
    }

    # Source IP ranges for variety
    src_ips = [
        "10.0.1.", "10.0.2.", "10.0.3.", "192.168.1.",
        "172.16.0.", "172.31.0.", "198.51.100.",
    ]
    dst_ips = [
        "8.8.8.8", "1.1.1.1", "10.0.0.1", "192.168.0.1",
        "8.8.4.4", "9.9.9.9", "1.0.0.1",
    ]

    alerts = []

    for i in range(n):
        # Random threat class
        tc = np.random.choice(threat_types)
        sevs = severity_map.get(tc, ["medium"])
        severity = np.random.choice(sevs)

        # Confidence varies by threat type and severity
        if severity == "critical":
            confidence = float(np.random.uniform(0.75, 0.95))
        elif severity == "high":
            confidence = float(np.random.uniform(0.6, 0.8))
        elif severity == "medium":
            confidence = float(np.random.uniform(0.4, 0.6))
        else:
            confidence = float(np.random.uniform(0.2, 0.4))

        # Generate realistic evidence based on threat type
        evidence = generate_evidence(tc, confidence)

        # Source/dest IPs
        src_ip_parts = np.random.choice(src_ips)
        dst_ip_parts = np.random.choice(dst_ips)
        source_ip = src_ip_parts + str(np.random.randint(2, 254))
        destination_ip = dst_ip_parts + str(np.random.randint(2, 254))

        # Protocol
        protocol = np.random.choice(["tcp", "udp", "icmp"],
                                    p=[0.6, 0.3, 0.1])

        # Ports
        source_port = np.random.randint(30000, 65535) if protocol == "tcp" else None
        destination_port = np.random.randint(80, 443) if protocol == "tcp" else None

        # Flow metrics
        packet_count = np.random.randint(10, 5000)
        bytes_transferred = np.random.randint(1000, 50_000_000)
        duration = round(float(np.random.uniform(0.5, 3600.0)), 2)

        # Flow ID
        flow_id = f"flow_{int(time.time())}_{i:04d}"

        # Model version
        model_versions = {
            "ddos": "isolation_forest_v1",
            "c2_beacon": "fft_beacon_detector_v1",
            "dga": "lightgbm_dga_v1",
            "tls_malware": "random_forest_ja3_v1",
            "port_scan": "statistical_scan_detector_v1",
            "exfiltration": "isolation_forest_exfil_v1",
        }
        model_version = model_versions.get(tc, "unknown")

        alert = {
            "alert_id": str(uuid.uuid4()),
            "timestamp": (datetime.now(timezone.utc) - timedelta(
                minutes=np.random.randint(0, 1440)
            )).isoformat(),
            "flow_id": flow_id,
            "threat_class": tc,
            "severity": severity,
            "confidence": round(confidence, 4),
            "source_ip": source_ip,
            "source_port": source_port,
            "destination_ip": destination_ip,
            "destination_port": destination_port,
            "protocol": protocol,
            "bytes_transferred": bytes_transferred,
            "packet_count": packet_count,
            "duration_seconds": duration,
            "evidence": evidence,
            "model_version": model_version,
            "raw_features": {
                "domain_entropy": round(float(np.random.uniform(2.0, 5.0)), 3),
                "packet_rate": round(float(np.random.uniform(10, 10000)), 2),
                "byte_rate": round(float(np.random.uniform(1000, 1000000)), 2),
            },
        }
        alerts.append(alert)

    return alerts


def generate_evidence(threat_class: str, confidence: float) -> List[Dict[str, Any]]:
    """Generate realistic evidence for a given threat class."""
    import random

    if threat_class == "ddos":
        return [
            {
                "feature_name": "syn_to_ack_ratio",
                "value": round(random.uniform(5.0, 50.0), 2),
                "contribution": round(random.uniform(0.2, 0.5), 2),
                "description": f"SYN flood detected: ratio {random.uniform(5.0, 50.0):.1f}:1",
            },
            {
                "feature_name": "packet_rate",
                "value": round(random.uniform(100, 5000), 2),
                "contribution": round(random.uniform(0.2, 0.5), 2),
                "description": f"High packet rate: {random.uniform(100, 5000):.1f} pps",
            },
        ]
    elif threat_class == "c2_beacon":
        return [
            {
                "feature_name": "periodicity_score",
                "value": round(random.uniform(0.3, 0.9), 4),
                "contribution": round(random.uniform(0.3, 0.5), 2),
                "description": f"Beacon periodicity score: {random.uniform(0.3, 0.9):.3f}",
            },
            {
                "feature_name": "inter_arrival_cv",
                "value": round(random.uniform(0.01, 0.1), 4),
                "contribution": round(random.uniform(0.2, 0.3), 2),
                "description": f"Low CV indicates periodic: {random.uniform(0.01, 0.1):.4f}",
            },
        ]
    elif threat_class == "dga":
        return [
            {
                "feature_name": "domain_entropy",
                "value": round(random.uniform(3.5, 5.0), 3),
                "contribution": round(random.uniform(0.3, 0.4), 2),
                "description": f"High domain entropy: {random.uniform(3.5, 5.0):.3f}",
            },
            {
                "feature_name": "digit_ratio",
                "value": round(random.uniform(0.2, 0.8), 3),
                "contribution": round(random.uniform(0.2, 0.3), 2),
                "description": f"High digit ratio: {random.uniform(0.2, 0.8):.3f}",
            },
        ]
    elif threat_class == "tls_malware":
        return [
            {
                "feature_name": "ja3",
                "value": f"synthetic_{uuid.uuid4().hex[:8]}",
                "contribution": round(random.uniform(0.3, 0.5), 2),
                "description": "JA3 fingerprint matches known malware",
            },
            {
                "feature_name": "packet_size_sequence",
                "value": f"{random.randint(400, 1500)} bytes",
                "contribution": round(random.uniform(0.2, 0.4), 2),
                "description": "Unusual packet size pattern",
            },
        ]
    elif threat_class == "port_scan":
        return [
            {
                "feature_name": "unique_dst_ports",
                "value": random.randint(25, 100),
                "contribution": round(random.uniform(0.4, 0.6), 2),
                "description": f"Unique destination ports: {random.randint(25, 100)}",
            },
            {
                "feature_name": "scan_type",
                "value": np.random.choice(["horizontal", "vertical"]),
                "contribution": round(random.uniform(0.2, 0.3), 2),
                "description": f"Scan type: {np.random.choice(['horizontal', 'vertical'])}",
            },
        ]
    elif threat_class == "exfiltration":
        return [
            {
                "feature_name": "outbound_inbound_ratio",
                "value": round(random.uniform(15.0, 100.0), 2),
                "contribution": round(random.uniform(0.35, 0.5), 2),
                "description": f"Outbound:inbound ratio: {random.uniform(15.0, 100.0):.1f}:1",
            },
            {
                "feature_name": "total_bytes_transferred",
                "value": random.randint(1_000_000, 50_000_000),
                "contribution": round(random.uniform(0.2, 0.3), 2),
                "description": f"Total bytes: {random.randint(1_000_000, 50_000_000) // 1024} KB",
            },
        ]
    else:
        return [
            {
                "feature_name": "feature_1",
                "value": random.random(),
                "contribution": 1.0,
                "description": "Generic feature",
            }
        ]


def seed_alerts(n: int = 50):
    """Seed the database with sample alerts."""
    print(f"Generating {n} sample alerts...")

    # Generate alerts
    alert_data_list = generate_sample_alerts(n=n)

    # Initialize database
    init_db_session()

    try:
        # Save each alert to database
        saved = 0
        for ad in alert_data_list:
            # Convert evidence to JSON
            evidence_json = json.dumps(ad["evidence"])

            # Convert raw_features to JSON
            raw_features_json = json.dumps(ad["raw_features"])

            # Parse timestamp
            ts = ad["timestamp"]
            if isinstance(ts, str):
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            else:
                dt = datetime.now(timezone.utc)

            # Create AlertRecord
            record = AlertRecord(
                alert_id=ad["alert_id"],
                timestamp=dt,
                threat_class=ad["threat_class"],
                severity=ad["severity"],
                confidence=ad["confidence"],
                source_ip=ad["source_ip"],
                source_port=ad.get("source_port"),
                destination_ip=ad["destination_ip"],
                destination_port=ad.get("destination_port"),
                protocol=ad["protocol"],
                bytes_transferred=ad["bytes_transferred"],
                packet_count=ad["packet_count"],
                duration_seconds=ad["duration_seconds"],
                evidence=evidence_json,
                model_version=ad["model_version"],
                raw_features=raw_features_json,
            )

            engine.session.add(record)
            saved += 1

        engine.session.commit()
        print(f"  Successfully saved {saved}/{n} alerts to database")

        # Print summary
        by_threat = {}
        by_severity = {}
        for ad in alert_data_list:
            by_threat[ad["threat_class"]] = by_threat.get(ad["threat_class"], 0) + 1
            by_severity[ad["severity"]] = by_severity.get(ad["severity"], 0) + 1

        print(f"  Distribution by threat class: {by_threat}")
        print(f"  Distribution by severity: {by_severity}")

    except Exception as e:
        engine.session.rollback()
        print(f"  ERROR: Failed to seed alerts: {e}")
        import traceback
        traceback.print_exc()

    finally:
        close_db_session()


def main():
    """Main entry point."""
    print("=" * 60)
    print("CyberSentinel Data Seeding")
    print("=" * 60)

    # Parse argument
    n = 50
    args = os.sys.argv[1:]
    for i, arg in enumerate(args):
        if arg.startswith("--count=") or arg.startswith("-c"):
            try:
                n = int(arg.split("=")[1] if "=" in arg else args[i + 1])
            except (ValueError, IndexError):
                pass

    seed_alerts(n=n)


if __name__ == "__main__":
    main()