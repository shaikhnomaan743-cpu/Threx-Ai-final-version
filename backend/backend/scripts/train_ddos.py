#!/usr/bin/env python3
"""Train DDoS anomaly detector using Isolation Forest.

This script:
1. Reads PCAP files from data/pcaps/
2. Extracts DDoS features (packet rate, byte rate, SYN/ACK ratio, entropy)
3. Trains Isolation Forest on anomaly features
4. Saves model to app/models/artifacts/ddos_detector.pkl
5. Prints training statistics and anomaly detection sample

Usage:
    python -m scripts.train_ddos
    # Or: make train-ddos
"""

import sys
import os
import glob
import time
from typing import List, Dict, Any

import numpy as np

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cybersentinel_backend.app.config import settings
from cybersentinel_backend.app.ingest.pcap_reader import pcap_reader, PacketInfo
from cybersentinel_backend.app.ingest.flow_builder import FlowBuilder, FlowState
from cybersentinel_backend.app.features.ddos_features import (
    extract_ddos_features,
    compute_syn_flood_ratio,
    compute_udp_amplification_ratio,
    compute_packet_rate,
    compute_byte_rate,
)
from cybersentinel_backend.app.alerts.schema import Evidence

# Import the detector module
from cybersentinel_backend.app.models.ddos_detector import DDOSDetector, get_ddos_detector

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PCAP_DIR = PROJECT_ROOT / "data" / "pcaps"
ARTIFACTS_DIR = PROJECT_ROOT / "app" / "models" / "artifacts"


def logger_info(msg: str):
    print(f"[train_ddos] {msg}", flush=True)


def logger_warn(msg: str):
    print(f"[train_ddos] WARNING: {msg}", flush=True)


def load_sample_pcaps() -> List[Any]:
    """Load sample PCAP files for training.

    Returns list ofPacketInfo objects from PCAP files found in data/pcaps/.
    """
    pcap_files = glob.glob(str(PCAP_DIR / "*.pcap"))
    pcap_files += glob.glob(str(PCAP_DIR / "*.pcapng"))

    if not pcap_files:
        logger_warn("No PCAP files found in data/pcaps/")
        # Create synthetic flow data for MVP
        logger_info("Creating synthetic flow data for DDoS training")
        return []

    packets = []
    for pcap_file in pcap_files[:5]:  # Limit for MVP training
        try:
            async for pkt in pcap_reader(pcap_file):
                packets.append(pkt)
                if len(packets) >= 5000:
                    break
            logger_info(f"Loaded {len(packets)} packets from {pcap_file}")
        except Exception as e:
            logger_warn(f"Error reading {pcap_file}: {e}")

    return packets


def extract_training_features(packets: List[Any]) -> Dict[str, np.ndarray]:
    """Extract DDoS training features from packet list.

    Returns feature dict with arrays for each feature type.
    """
    # Group into flows using FlowBuilder
    flow_builder = FlowBuilder(ttl_seconds=60)
    flow_keys = []

    for pkt in packets:
        key = flow_builder.add_packet(pkt)
        flow_keys.append(key)

    # Get all flows
    flows = flow_builder.get_flows()

    # Extract features from each flow
    feature_vectors = []
    labels = []  # 0=benign, 1=DDoS

    for flow_key, flow in flows.items():
        features = extract_ddos_features(flow)

        # Build feature vector
        vec = np.array([
            features.get("packet_rate", 0),
            features.get("byte_rate", 0),
            features.get("syn_to_ack_ratio", 0),
            features.get("amplification_ratio", 0),
            features.get("dst_port_count", 0),
            features.get("syn_rate", 0),
            features.get("packet_count", 0),
            features.get("bytes_transferred", 0),
        ])

        # Label: heuristic-based for synthetic data
        # DDoS-like: high packet rate + high SYN ratio
        is_ddos = (
            features.get("packet_rate", 0) > 1000
            and features.get("syn_to_ack_ratio", 0) > 5.0
        )

        feature_vectors.append(vec)
        labels.append(1 if is_ddos else 0)

    if not feature_vectors:
        # Create synthetic training data for MVP
        logger_info("Creating synthetic DDoS training data")
        np.random.seed(42)
        n_benign = 500
        n_ddos = 200

        # Benign: moderate packet rates, low SYN ratio
        X_benign = np.random.normal(
            loc=[500, 1000, 1.0, 5.0, 5, 0.1, 100, 50000],
            scale=[100, 200, 0.5, 2.0, 2, 0.05, 20, 10000],
            size=(n_benign, 8),
        )
        # Ensure positive values
        X_benign = np.abs(X_benign)

        # DDoS: high packet rates, high SYN ratio
        X_ddos = np.random.normal(
            loc=[2000, 5000, 50.0, 100.0, 100, 0.8, 5000, 200000],
            scale=[500, 1000, 10.0, 30.0, 20, 0.1, 1000, 50000],
            size=(n_ddos, 8),
        )
        X_ddos = np.abs(X_ddos)

        feature_vectors = list(X_benign) + list(X_ddos)
        labels = [0] * n_benign + [1] * n_ddos

    X = np.array(feature_vectors)
    y = np.array(labels)

    return {"X": X, "y": y}


def train():
    """Train the DDoS Isolation Forest detector."""
    print("=" * 60)
    print("CyberSentinel DDoS Detector Training")
    print("=" * 60)

    # Step 1: Load data
    print("\n[1/5] Loading training data...")
    packets = load_sample_pcaps()
    features_dict = extract_training_features(packets)
    X = features_dict["X"]
    y = features_dict["y"]

    print(f"  Feature matrix shape: {X.shape}")
    print(f"  Label distribution: {dict(zip(*np.unique(y, return_counts=True))}")

    if X.shape[0] < 20:
        print("  WARNING: Too little training data. Using synthetic data only.")

    # Step 2: Train Isolation Forest
    print("\n[2/5] Training Isolation Forest model...")
    try:
        from sklearn.ensemble import IsolationForest

        contamination = float(y.sum()) / max(len(y), 1)
        logger_info(f"  Estimated contamination: {contamination:.4f}")

        iforest = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100,
        )

        # Scale features
        from sklearn.preprocessing import StandardScaler
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        iforest.fit(X_scaled)

        # Evaluate: training anomaly score stats
        decision_scores = iforest.decision_function(X_scaled)
        train_anomaly_mean = float(np.mean(decision_scores[y == 1]))
        train_anomaly_normal = float(np.mean(decision_scores[y == 0]))
        train_auc = float(roc_auc_score(y, -decision_scores))  # Higher score = more normal

        print(f"  Train AUC (anomaly vs normal): {train_auc:.4f}")
        print(f"  Normal flow score mean: {train_anomaly_normal:.4f}")
        print(f"  Anomaly flow score mean: {train_anomaly_mean:.4f}")
        print(f"  (Lower scores = more anomalous)")

        # Step 3: Save model and scaler
        print("\n[3/5] Saving model artifacts...")
        ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

        import joblib

        model_path = ARTIFACTS_DIR / "ddos_detector.joblib"
        scaler_path = ARTIFACTS_DIR / "ddos_scaler.joblib"

        joblib.dump(iforest, model_path)
        joblib.dump(scaler, scaler_path)

        print(f"  Model saved to: {model_path}")
        print(f"  Scaler saved to: {scaler_path}")

        # Step 4: Test inference on sample
        print("\n[4/5] Testing inference on sample flows...")
        test_scores = iforest.decision_function(X_scaled)
        for i in range(min(5, len(X))):
            is_anomaly = iforest.predict(X_scaled[i:i+1])[0] == -1
            print(f"  Sample {i}: anomaly={is_anomaly}, score={test_scores[i]:.4f}")

        print("=" * 60)
        print("DDoS training complete!")
        print("=" * 60)

    except ImportError as e:
        print(f"  ERROR: Missing dependency: {e}")
        print("  Install with: pip install scikit-learn")
        sys.exit(1)
    except Exception as e:
        print(f"  ERROR: Training failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    train()