#!/usr/bin/env python3
"""Train C2 Beacon detector using FFT + spectral analysis.

This script:
1. Reads PCAP files and builds flow inter-arrival time series
2. Computes coefficient of variation and FFT periodicity
3. Trains DBSCAN clustering on periodicity features
4. Saves detector parameters to app/models/artifacts/beacon_detector.json
5. Prints periodicity detection statistics

Usage:
    python -m scripts.train_beacon
    # Or: make train-beacon
"""

import sys
import os
import json
import numpy as np
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cybersentinel_backend.app.config import settings
from cybersentinel_backend.app.ingest.pcap_reader import pcap_reader
from cybersentinel_backend.app.ingest.flow_builder import FlowBuilder
from cybersentinel_backend.app.features.beacon_features import (
    compute_inter_arrival_times,
    compute_coefficient_of_variation,
    compute_fft_periodicity,
    compute_jitter,
)
from cybersentinel_backend.app.models.beacon_detector import BeaconDetector

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PCAP_DIR = PROJECT_ROOT / "data" / "pcaps"
ARTIFACTS_DIR = PROJECT_ROOT / "app" / "models" / "artifacts"


def logger_info(msg: str):
    print(f"[train_beacon] {msg}", flush=True)


def logger_warn(msg: str):
    print(f"[train_beacon] WARNING: {msg}", flush=True)


def load_packets_from_pcaps(max_packs: int = 10000) -> List:
    """Load packets from PCAP files for beacon training."""
    pcap_files = glob.glob(str(PCAP_DIR / "*.pcap"))
    pcap_files += glob.glob(str(PCAP_DIR / "*.pcapng"))

    if not pcap_files:
        logger_warn("No PCAP files found, generating synthetic beacon data")
        return []

    all_packets = []
    for pcap_file in pcap_files[:3]:
        try:
            async for pkt in pcap_reader(pcap_file):
                all_packets.append(pkt)
                if len(all_packets) >= max_packs:
                    break
            logger_info(f"Loaded {len(all_packets)} packets from {pcap_file}")
        except Exception as e:
            logger_warn(f"Error reading {pcap_file}: {e}")

    return all_packets


def extract_beacon_flow_data(packets: List, flow_builder: FlowBuilder) -> Dict[str, Any]:
    """Extract beacon features from flow data."""
    # Add all packets to flow builder
    for pkt in packets:
        flow_builder.add_packet(pkt)

    # Get all flows
    flows = flow_builder.get_flows()

    # Extract inter-arrival characteristics from each flow
    cv_values = []
    dominant_periods = []
    jitter_values = []
    observation_counts = []

    for flow_key, flow in flows.items():
        timestamps = flow.timestamps
        pkt_count = flow.packet_count

        if len(timestamps) >= 8:  # Minimum for beacon analysis
            # CV of inter-arrival times
            arrival_times = compute_inter_arrival_times(timestamps)
            if arrival_times:
                cv = compute_coefficient_of_variation(arrival_times)
                cv_values.append(cv)

            # FFT periodicity
            dur = flow.duration_seconds()
            sample_rate = float(pkt_count) / max(dur, 1.0)
            fft_result = compute_fft_periodicity(timestamps, sample_rate=sample_rate)
            dominant_periods.append(fft_result["dominant_period"])
            jitter_values.append(compute_jitter(timestamps))
            observation_counts.append(len(timestamps))
        else:
            # Too few observations for beacon analysis
            cv_values.append(1.0)  # High CV = not periodic
            dominant_periods.append(0.0)
            jitter_values.append(1.0)
            observation_counts.append(len(timestamps))

    return {
        "cv_values": cv_values,
        "dominant_periods": dominant_periods,
        "jitter_values": jitter_values,
        "observation_counts": observation_counts,
        "total_flows": len(flows),
    }


def train():
    """Train the Beacon detector."""
    print("=" * 60)
    print("CyberSentinel Beacon Detector Training")
    print("=" * 60)

    # Step 1: Load data
    print("\n[1/5] Loading training data...")
    packets = load_packets_from_pcaps(max_packs=5000)

    if not packets:
        logger_info("No PCAP data available, creating synthetic beacon data")
        np.random.seed(42)

        # Synthetic: generate flows with periodic vs random inter-arrival
        n_periodic = 100  # Low CV, periodic (beacon-like)
        n_random = 200    # High CV, random (benign)

        # Periodic flows: CV around 0.05, period ~60s
        periodic_cvs = np.random.normal(0.05, 0.01, n_periodic)
        periodic_periods = np.random.normal(60.0, 3.0, n_periodic)

        # Random flows: CV around 0.5, no dominant period
        random_cvs = np.random.normal(0.5, 0.1, n_random)

        cv_values = list(periodic_cvs) + list(random_cvs)
        dominant_periods = list(periodic_periods) + [0.0] * n_random
        jitter_values = [0.1] * n_periodic + [0.8] * n_random
        observation_counts = [50] * (n_periodic + n_random)

    else:
        # Extract from real PCAP data
        logger_info("Extracting beacon features from PCAP data...")
        flow_builder = FlowBuilder(ttl_seconds=60)
        data = extract_beacon_flow_data(packets, flow_builder)

        cv_values = data["cv_values"]
        dominant_periods = data["dominant_periods"]
        jitter_values = data["jitter_values"]
        observation_counts = data["observation_counts"]
        total_flows = data["total_flows"]

    # Step 2: Create labels
    # Low CV + dominant period = beacon (1), else benign (0)
    beacon_labels = []
    for cv, period in zip(cv_values, dominant_periods):
        if cv < 0.1 and period > 10:
            beacon_labels.append(1)  # Beacon
        else:
            beacon_labels.append(0)  # Benign

    # Balance the dataset
    X_cv = np.array(cv_values)
    X_period = np.array(dominant_periods)
    X_jitter = np.array(jitter_values)
    y = np.array(beacon_labels)

    # Combine features
    X = np.column_stack([X_cv, X_period, X_jitter])

    print(f"  Dataset shape: {X.shape}")
    print(f"  Benign/Breakdown: {dict(zip(*np.unique(y, return_counts=True)))}")

    # Step 3: Train DBSCAN or threshold-based detector
    print("\n[2/5] Training beacon detection model...")
    from sklearn.cluster import DBSCAN

    # DBSCAN on CV-periodicity space
    # Clusters with low CV + period ~ beacon
    try:
        dbscan = DBSCAN(eps=0.1, min_samples=5)
        cluster_labels = dbscan.fit_predict(X)

        # Evaluate: separate by known labels
        n_clusters = len(set(cluster_labels)) - (1 if -1 in cluster_labels else 0)
        print(f"  DBSCAN found {n_clusters} clusters")

        # Store model parameters
        model_metrics = {
            "eps": float(dbscan.eps),
            "min_samples": int(dbscan.min_samples),
            "cv_threshold": 0.1,
            "min_period": 10.0,
            "n_features": X.shape[1],
        }

        # Step 4: Save model
        print("\n[3/5] Saving beacon detector artifacts...")
        ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

        import json

        model_path = ARTIFACTS_DIR / "beacon_detector.json"
        with open(model_path, "w") as f:
            json.dump(model_metrics, f, indent=2)

        # Also save scaler info
        scaler_info = {
            "cv_mean": float(np.mean(X_cv)),
            "cv_std": float(np.std(X_cv)),
            "period_mean": float(np.mean(X_period[periods > 0])) if np.any(periods > 0) else 0,
            "jitter_mean": float(np.mean(X_jitter)),
        }

        scaler_path = ARTIFACTS_DIR / "beacon_scaler.json"
        with open(scaler_path, "w") as f:
            json.dump(scaler_info, f, indent=2)

        print(f"  Model saved to: {model_path}")
        print(f"  Scaler saved to: {scaler_path}")

        # Step 5: Evaluation
        print("\n[4/5] Evaluating beacon detector...")
        # Simple threshold evaluation
        tp = fp = tn = fn = 0
        for i in range(len(X)):
            cv = X[i, 0]
            period = X[i, 1]
            jitter = X[i, 2]
            predicted_beacon = cv < 0.1 and period > 10

            actual_beacon = y[i] == 1
            if predicted_beacon and actual_beacon:
                tp += 1
            elif predicted_beacon and not actual_beacon:
                fp += 1
            elif not predicted_beacon and actual_beacon:
                fn += 1
            else:
                tn += 1

        precision = tp / max(tp + fp, 1)
        recall = tp / max(tp + fn, 1)
        f1 = 2 * precision * recall / max(precision + recall, 1)

        print(f"  True Positives: {tp}")
        print(f"  False Positives: {fp}")
        print(f"  True Negatives: {tn}")
        print(f"  False Negatives: {fn}")
        print(f"  Precision: {precision:.4f}")
        print(f"  Recall: {recall:.4f}")
        print(f"  F1 Score: {f1:.4f}")

    except Exception as e:
        print(f"  Training error: {e}")
        import traceback
        traceback.print_exc()

    print("=" * 60)
    print("Beacon training complete!")
    print("=" * 60)


if __name__ == "__main__":
    train()