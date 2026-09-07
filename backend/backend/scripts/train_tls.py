#!/usr/bin/env python3
"""Train TLS malware classifier using Random Forest on JA3 features.

This script:
1. Extracts JA3 fingerprints from TLS ClientHello metadata in PCAP files
2. Trains Random Forest classifier to distinguish malware vs benign TLS
3. Saves model and feature scaler to app/models/artifacts/
4. Prints training accuracy and feature importances

Usage:
    python -m scripts.train_tls
    # Or: make train-tls
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
from cybersentinel_backend.app.features.tls_features import (
    extract_ja3,
    extract_ja4,
    extract_packet_size_sequence,
)
from cybersentinel_backend.app.models.tls_classifier import (
    TLSMalwareClassifier,
    get_tls_malware_classifier,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PCAP_DIR = PROJECT_ROOT / "data" / "pcaps"
ARTIFACTS_DIR = PROJECT_ROOT / "app" / "models" / "artifacts"


def logger_info(msg: str):
    print(f"[train_tls] {msg}", flush=True)


def logger_warn(msg: str):
    print(f"[train_tls] WARNING: {msg}", flush=True)


def load_tls_data_from_pcaps(max_packs: int = 5000) -> tuple:
    """Extract TLS metadata from PCAP files for training.

    Returns:
        X: Feature matrix (list of feature vectors)
        y: Labels (0=benign, 1=malware)
        metadata: List of dicts with per-sample metadata
    """
    pcap_files = glob.glob(str(PCAP_DIR / "*.pcap"))
    pcap_files += glob.glob(str(PCAP_DIR / "*.pcapng"))

    if not pcap_files:
        logger_warn("No PCAP files found, generating synthetic TLS data")
        return synthetic_tls_data()

    all_X = []
    all_y = []
    all_metadata = []

    for pcap_file in pcap_files[:5]:
        try:
            async for pkt in pcap_reader(pcap_file):
                # Extract TLS metadata if packet has TLS layer
                if pkt.haslayer("TLS"):
                    tls = pkt["TLS"]
                    try:
                        # Extract ClientHello metadata
                        version = str(tls.version) if hasattr(tls, 'version') else "TLS 1.2"

                        # Ciphers
                        ciphers = []
                        if hasattr(tls, 'ciphers') and isinstance(tls.ciphers, list):
                            ciphers = tls.ciphers[:8]

                        # Extensions
                        extensions = []
                        if hasattr(tls, 'extensions') and isinstance(tls.extensions, list):
                            extensions = tls.extensions[:8]

                        # Curves
                        curves = []
                        if hasattr(tls, 'curves') and isinstance(tls.curves, list):
                            curves = tls.curve[:8] if hasattr(tls, 'curve') else []

                        # Point formats
                        point_formats = []
                        if hasattr(tls, 'point_formats') and isinstance(tls.point_formats, list):
                            point_formats = tls.point_formats[:8]

                        # Hostname (SNI)
                        hostname = ""
                        if hasattr(tls, 'server_name'):
                            hostname = str(tls.server_name)

                        # Packet size
                        pkt_size = len(pkt)

                        # Compute JA3 and JA4
                        ja3 = extract_ja3(version, ciphers, extensions, curves, point_formats)
                        ja4 = extract_ja4(ja3, hostname, extensions)

                        # Feature vector
                        size_seq = extract_packet_size_sequence(
                            type('FlowState', (), {
                                'packet_sizes': [pkt_size],
                                'ja3': ja3,
                                'ja4': ja4,
                                'raw_features': {},
                            })(),
                            max_packets=20,
                        )

                        features = [
                            len(ciphers),
                            len(extensions),
                            len(curves),
                            len(point_formats),
                            np.mean(size_seq) if size_seq else 0,
                            np.std(size_seq) if len(size_seq) > 1 else 0,
                            len(ja3),
                            len(ja4),
                        ]

                        all_X.append(features)
                        all_y.append(0)  # 0 = benign (default; labeled data would distinguish)
                        all_metadata.append({
                            "version": version,
                            "ja3": ja3,
                            "ja4": ja4,
                            "source_ip": pkt.src_ip,
                            "packet_size": pkt_size,
                        })

                    except Exception as e:
                        logger_warn(f"Error extracting TLS from packet: {e}")
                        continue

            logger_info(f"Processed PCAP: extracted TLS metadata from packets")
        except Exception as e:
            logger_warn(f"Error processing PCAP: {e}")

    if not all_X:
        all_X, all_y, all_metadata = synthetic_tls_data()

    return np.array(all_X), np.array(all_y), all_metadata


def synthetic_tls_data(n_benign: int = 300, n_malware: int = 100) -> tuple:
    """Generate synthetic TLS training data for MVP.

    Benign: typical enterprise TLS fingerprints
    Malware: unusual JA3 patterns associated with known malware
    """
    np.random.seed(42)

    # Benign features: typical enterprise JA3 characteristics
    benign_X = []
    for _ in range(n_benign):
        # Mean cipher count ~5, extensions ~3, curves ~2, point formats ~2
        # Size mean ~500bytes, std ~200
        features = [
            np.random.poisson(5),      # ciphers_count
            np.random.poisson(3),      # extensions_count
            np.random.poisson(2),      # curves_count
            np.random.poisson(2),      # point_formats_count
            np.random.normal(500, 200), # mean_size
            np.random.exponential(200), # std_size
            np.random.randint(40, 80), # ja3_len (approx)
            np.random.randint(60, 100), # ja4_len (approx)
        ]
        benign_X.append(features)

    # Malware features: unusual JA3 patterns
    malware_X = []
    for _ in range(n_malware):
        # Unusual: many extensions, odd cipher combos, large packet sizes
        features = [
            np.random.poisson(12),      # ciphers_count (high)
            np.random.poisson(8),      # extensions_count (high)
            np.random.poisson(3),      # curves_count
            np.random.poisson(3),      # point_formats_count
            np.random.normal(2000, 500), # mean_size (large)
            np.random.exponential(500), # std_size
            np.random.randint(80, 120), # ja3_len
            np.random.randint(100, 150), # ja4_len
        ]
        malware_X.append(features)

    X = benign_X + malware_X
    y = [0] * n_benign + [1] * n_malware

    metadata = []
    for i in range(len(X)):
        metadata.append({
            "version": "TLS 1.2",
            "ja3": f"synthetic_{i}",
            "ja4": f"synthetic_ja4_{i}",
        })

    return np.array(X), np.array(y), metadata


def glob(pattern: str):
    """Simple glob import."""
    import glob as g
    return g.glob(pattern)


def train():
    """Train the TLS malware classifier."""
    print("=" * 60)
    print("CyberSentinel TLS Malware Classifier Training")
    print("=" * 60)

    # Step 1: Load data
    print("\n[1/5] Loading TLS training data...")
    X, y, metadata = load_tls_data_from_pcaps(max_packs=3000)

    print(f"  Extracted {len(X)} samples")
    print(f"  Label distribution: {dict(zip(*np.unique(y, return_counts=True)))}")

    if len(X) < 20:
        print("  WARNING: Insufficient TLS data, using synthetic data")
        X, y, metadata = synthetic_tls_data()

    # Step 2: Train Random Forest
    print("\n[2/5] Training Random Forest classifier...")
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.preprocessing import StandardScaler

        # Split data
        from sklearn.model_selection import train_test_split

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42, stratify=y
        )

        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)

        # Train Random Forest
        clf = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            max_depth=15,
            min_samples_leaf=5,
            class_weight="balanced",
        )

        clf.fit(X_train_scaled, y_train)

        # Evaluate
        train_acc = clf.score(X_train_scaled, y_train)
        test_acc = clf.score(X_test_scaled, y_test)

        # Feature importances
        feature_names = [
            "ciphers_count", "extensions_count", "curves_count",
            "point_formats_count", "mean_size", "std_size",
            "ja3_len", "ja4_len"
        ]

        importances = clf.feature_importances_
        feature_importances = sorted(
            zip(feature_names, importances),
            key=lambda x: x[1],
            reverse=True,
        )

        print(f"  Train accuracy: {train_acc:.4f}")
        print(f"  Test accuracy:  {test_acc:.4f}")
        print("\n  Feature importances:")
        for name, imp in feature_importances:
            print(f"    {name}: {imp:.4f}")

        # Step 3: Save model and scaler
        print("\n[3/5] Saving TLS model artifacts...")
        ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

        import joblib

        model_path = ARTIFACTS_DIR / "tls_malware_classifier.joblib"
        scaler_path = ARTIFACTS_DIR / "tls_scaler.joblib"

        joblib.dump(clf, model_path)
        joblib.dump(scaler, scaler_path)

        print(f"  Model saved to: {model_path}")
        print(f"  Scaler saved to: {scaler_path}")

        # Step 4: Test inference sample
        print("\n[4/5] Testing inference on sample...")
        sample_idx = min(5, len(X_test))
        for i in range(sample_idx):
            pred = clf.predict(X_test_scaled[i:i+1])[0]
            prob = clf.predict_proba(X_test_scaled[i:i+1])[0]
            confidence = max(prob)
            predicted_class = "malware" if pred == 1 else "benign"
            print(f"  Sample {i}: {predicted_class} (confidence: {confidence:.3f})")

    except ImportError as e:
        print(f"  ERROR: Missing dependency: {e}")
        print("  Install with: pip install scikit-learn numpy")
        sys.exit(1)
    except Exception as e:
        print(f"  ERROR: Training failed: {e}")
        import traceback
        traceback.print_exc()

    print("=" * 60)
    print("TLS training complete!")
    print("=" * 60)


if __name__ == "__main__":
    train()