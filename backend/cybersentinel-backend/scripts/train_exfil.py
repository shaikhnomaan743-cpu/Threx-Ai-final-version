#!/usr/bin/env python3
"""Train Exfiltration detector using Isolation Forest.

This script:
1. Reads PCAP files and extracts flow-level byte ratio features
2. Trains Isolation Forest on exfiltration anomaly features
3. Saves model to app/models/artifacts/exfil_detector.pkl
4. Prints anomaly detection statistics

Usage:
    python -m scripts.train_exfil
    # Or: make train-exfil
"""

import sys
import os
import glob
import numpy as np
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cybersentinel_backend.app.config import settings
from cybersentinel_backend.app.ingest.pcap_reader import pcap_reader
from cybersentinel_backend.app.ingest.flow_builder import FlowBuilder
from cybersentinel_backend.app.features.exfil_features import (
    compute_outbound_inbound_ratio,
    compute_session_duration_stats,
    compute_byte_skew,
    extract_exfil_features,
)
from cybersentinel_backend.app.models.exfil_detector import ExfiltrationDetector

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PCAP_DIR = PROJECT_ROOT / "data" / "pcaps"
ARTIFACTS_DIR = PROJECT_ROOT / "app" / "models" / "artifacts"


def logger_info(msg: str):
    print(f"[train_exfil] {msg}", flush=True)


def logger_warn(msg: str):
    print(f"[train_exfil] WARNING: {msg}", flush=True)


def load_pcap_flows(n_flows: int = 2000) -> FlowBuilder:
    """Load flows from PCAP files for exfiltration training."""
    pcap_files = glob.glob(str(PCAP_DIR / "*.pcap"))
    pcap_files += glob.glob(str(PCAP_DIR / "*.pcapng"))

    flow_builder = FlowBuilder(ttl_seconds=60)

    if not pcap_files:
        logger_warn("No PCAP files found, generating synthetic exfil data")
        return flow_builder

    count = 0
    for pcap_file in pcap_files[:5]:
        if count >= n_flows:
            break
        try:
            async for pkt in pcap_reader(pcap_file):
                flow_builder.add_packet(pkt)
                count += 1
                if count >= n_flows:
                    break
            logger_info(f"Loaded {count} packets from {pcap_file}")
        except Exception as e:
            logger_warn(f"Error reading {pcap_file}: {e}")

    return flow_builder


def train():
    """Train the Exfiltration detector."""
    print("=" * 60)
    print("CyberSentinel Exfiltration Detector Training")
    print("=" * 60)

    # Step 1: Load data
    print("\n[1/5] Loading training data...")
    flow_builder = load_pcap_flows(n_flows=3000)

    # Extract features from all flows
    all_features = []
    for flow_key, flow in flow_builder.get_flows().items():
        features = extract_exfil_features(flow)
        all_features.append({
            "outbound_bytes": features.get("outbound_bytes", 0),
            "inbound_bytes": features.get("inbound_bytes", 0),
            "ratio": features.get("ratio", 0.0),
            "duration_seconds": features.get("duration_seconds", 0.0),
            "throughput_bytes_sec": features.get("throughput_bytes_sec", 0.0),
            "byte_skew": features.get("byte_skew", 0.0),
            "total_bytes": features.get("total_bytes", 0),
            "exfil_likely": features.get("exfil_alert", False),
        })

    if not all_features:
        logger_warn("No flow data, generating synthetic exfil data")
        np.random.seed(42)

        # Synthetic: create flows with varying byte ratios
        n_normal = 1000  # Normal bidirectional traffic
        n_exfil = 200    # Exfiltration-like traffic

        # Normal: ratio around 1:1
        normal_ratios = np.random.normal(1.0, 0.5, n_normal)
        normal_tp = np.random.uniform(1000, 50000, n_normal)  # throughput
        normal_dur = np.random.uniform(1.0, 300.0, n_normal)  # duration
        normal_ob = np.random.uniform(1000, 10000, n_normal)  # outbound bytes
        normal_ib = np.random.uniform(1000, 10000, n_normal)  # inbound bytes

        # Exfil: ratio > 10:1, high total volume
        exfil_ratios = np.random.uniform(15.0, 100.0, n_exfil)
        exfil_tp = np.random.uniform(5000, 100000, n_exfil)
        exfil_dur = np.random.uniform(5.0, 300.0, n_exfil)
        exfil_ob = np.random.uniform(500000, 50000000, n_exfil)  # >10MB outbound
        exfil_ib = np.random.uniform(1000, 100000, n_exfil)  # small inbound

        all_features = []
        for i in range(n_normal):
            total = normal_ob[i] + normal_ib[i]
            ratio = normal_ob[i] / max(normal_ib[i], 1)
            throughput = normal_tp[i] / max(normal_dur[i], 1)
            skew = abs(normal_ob[i] - normal_ib[i]) / max(total, 1)
            all_features.append({
                "outbound_bytes": int(normal_ob[i]),
                "inbound_bytes": int(normal_ib[i]),
                "ratio": round(ratio, 4),
                "duration_seconds": round(float(normal_dur[i]), 2),
                "throughput_bytes_sec": round(float(throughput), 2),
                "byte_skew": round(float(skew), 4),
                "total_bytes": int(total),
                "exfil_likely": ratio > 10 and total > 10 * 1024 * 1024,
            })

        for i in range(n_exfil):
            total = exfil_ob[i] + exfil_ib[i]
            ratio = exfil_ob[i] / max(exfil_ib[i], 1)
            throughput = exfil_tp[i] / max(exfil_dur[i], 1)
            skew = abs(exfil_ob[i] - exfil_ib[i]) / max(total, 1)
            all_features.append({
                "outbound_bytes": int(exfil_ob[i]),
                "inbound_bytes": int(exfil_ib[i]),
                "ratio": round(float(ratio), 4),
                "duration_seconds": round(float(exfil_dur[i]), 2),
                "throughput_bytes_sec": round(float(throughput), 2),
                "byte_skew": round(float(skew), 4),
                "total_bytes": int(total),
                "exfil_likely": True,
            })

    # Build feature matrix
    X = np.array([
        [f["outbound_bytes"], f["inbound_bytes"], f["ratio"],
         f["duration_seconds"], f["byte_skew"], f["throughput_bytes_sec"]]
        for f in all_features
    ], dtype=float)

    y = np.array([1 if f["exfil_likely"] else 0 for f in all_features])

    print(f"  Feature matrix shape: {X.shape}")
    print(f"  Label distribution: {dict(zip(*np.unique(y, return_counts=True)))}")

    # Step 2: Train Isolation Forest
    print("\n[2/5] Training Isolation Forest anomaly detector...")
    try:
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler

        contamination = float(y.sum()) / max(len(y), 1)
        logger_info(f"  Estimated contamination: {contamination:.4f}")

        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        iforest = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100,
        )

        iforest.fit(X_scaled)

        # Evaluate
        decision_scores = iforest.decision_function(X_scaled)
        pred_anomalies = iforest.predict(X_scaled) == -1

        # Classification report
        tp = int((pred_anomalies & (y == 1)).sum())
        fp = int((pred_anomalies & (y == 0)).sum())
        tn = int((~pred_anomalies & (y == 0)).sum())
        fn = int((~pred_anomalies & (y == 1)).sum())

        precision = tp / max(tp + fp, 1)
        recall = tp / max(tp + fn, 1)
        f1 = 2 * precision * recall / max(precision + recall, 1)

        print(f"  True Positives (exfil detected): {tp}")
        print(f"  False Positives (normal flagged): {fp}")
        print(f"  True Negatives (normal passed): {tn}")
        print(f"  False Negatives (exfil missed): {fn}")
        print(f"  Precision: {precision:.4f}")
        print(f"  Recall: {recall:.4f}")
        print(f"  F1 Score: {f1:.4f}")
        print(f"  AUC: {roc_auc_score(y, -decision_scores):.4f}")

        # Step 3: Save model and scaler
        print("\n[3/5] Saving exfiltration detector artifacts...")
        ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

        import joblib

        model_path = ARTIFACTS_DIR / "exfil_detector.joblib"
        scaler_path = ARTIFACTS_DIR / "exfil_scaler.joblib"

        joblib.dump(iforest, model_path)
        joblib.dump(scaler, scaler_path)

        print(f"  Model saved to: {model_path}")
        print(f"  Scaler saved to: {scaler_path}")

        # Step 4: Test inference
        print("\n[4/5] Testing inference on sample flows...")
        test_scores = iforest.decision_function(X_scaled)
        for i in range(min(5, len(X))):
            is_anomaly = int(test_scores[i] < 0)
            print(f"  Sample {i}: anomaly={is_anomaly}, score={test_scores[i]:.4f}, "
                  f"true_label={int(y[i])}")

    except Exception as e:
        print(f"  ERROR: Training failed: {e}")
        import traceback
        traceback.print_exc()

    print("=" * 60)
    print("Exfiltration training complete!")
    print("=" * 60)


if __name__ == "__main__":
    train()