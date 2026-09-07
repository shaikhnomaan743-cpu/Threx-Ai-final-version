# Model Documentation — Threx AI

**All model evaluation metrics are computed on Scapy-generated lab traffic matching real-tool statistical signatures (see `data/DATASETS.md`). These are *synthetic-derived* evaluations, not assessed on independent real-world traffic. Metrics are included for reproducibility and comparison, not as claims of real-world performance.**

---

## 1. DDoS Detector — IsolationForest

- **Model/technique**: `IsolationForest` (scikit-learn) trained on synthetic flow-rate features with contamination 0.05. Anomaly scores isolate abnormal traffic patterns (high packet rate, high byte rate) from benign baselines.
- **Why it fits**: DDoS attacks manifest as sudden surges in packet/byte rates that are statistically rare compared to legitimate traffic. IsolationForest effectively separates these outliers without needing labeled attack examples.
- **Features engineered**:
  - `packet_rate` — packets per second (anomalous when > 1000 pps)
  - `byte_rate` — bytes per second (anomalous when > 100 KB/s)
  - `syn_to_ack_ratio` — SYN/ACK ratio > 10:1 indicates SYN flood
  - `amplification_ratio` — UDP amplification ratio > 20:1
- **Training/validation approach**: 
  - Dataset: Scapy-generated lab traffic (300 benign + 300 attack flow rates) + CIC-IDS-2017 distilled statistics
  - Train/test split: 80/20
  - Metrics: `test_auc = 0.9967` (on synthetic derived hold-out set)
  - **Caveat**: AUC evaluated on synthetic derived dataset; real-world traffic patterns may differ. See `data/models/evaluation.json` and `data/DATASETS.md`.

---

## 2. C2 Beaconing Detector — FFT Periodicity + CV Analysis

- **Model/technique**: Rule-based detector using Fast Fourier Transform (FFT) periodicity score and inter-arrival coefficient of variation (CV). Flagged when `cv < 0.1 and periodicity_score > 0.2`.
- **Why it fits**: C2 beacons exhibit periodic timing patterns with low variance in inter-arrival intervals. The FFT detects dominant periodicities, while CV measures timing consistency.
- **Features engineered**:
  - `periodicity_score` — FFT dominant periodicity score (periodic if > 0.2)
  - `dominant_period` — estimated beacon interval in seconds
  - `inter_arrival_cv` — coefficient of variation of inter-arrival times (low = periodic)
  - `jitter` — timing consistency = `1 - cv`
  - `destination_rarity` — fixed at 0.5 (unknown target)
- **Training/validation approach**:
  - Dataset: Scapy-generated lab traffic with configurable beacon intervals (60s nominal, 5% jitter) + CTU-13 statistical summaries
  - No train/test split (rule-based thresholds tuned on validation set)
  - Metrics: `accuracy = 1.0` (on synthetic derived test set, tp=100, tn=100, fp=0, fn=0)
  - **Caveat**: Accuracy evaluated on synthetic derived dataset with fixed beacon interval; real beacons may have variable jitter. See `data/models/evaluation.json` and `data/DATASETS.md`.

---

## 3. DGA Classifier — LightGBM

- **Model/technique**: LightGBM gradient boosting classifier on domain name features. Trained to distinguish legitimate domains (Tranco top 1M) from malicious DGA-generated domains.
- **Why it fits**: DGA domains exhibit high entropy, abnormal digit/consonant-vowel ratios, and increased length. LightGBM captures these nonlinear patterns effectively.
- **Features engineered**:
  - `domain_entropy` — Shannon entropy of domain name (> 3.5 indicates DGA-like)
  - `bigram_log_likelihood_3` — log-likelihood of trigrams under benign distribution
  - `digit_ratio` — fraction of digits in domain name (DGA domains often have high digit ratios)
  - `consonant_vowel_ratio` — ratio of consonants to vowels
- **Training/validation approach**:
  - Dataset: 1000 Tranco benign domains + 5000 DGArchive-derived synthetic malicious domains (entropy > 3.5, length 8–20)
  - Train/test split: 80/20
  - Metrics: `train_auc = 0.9991, test_auc = 1.0` (on synthetic derived hold-out)
  - **Caveat**: test AUC = 1.0 on synthetic derived set; real DGA domains may vary. Replace with official DGArchive export for production retraining. See `data/DATASETS.md`.

---

## 4. TLS Malware Classifier — RandomForest

- **Model/technique**: `RandomForestClassifier` (scikit-learn) on JA3 fingerprint features + TLS handshake metadata. Detects malware-controlled TLS connections based on cipher/extension/curve patterns.
- **Why it fits**: Malware connections often use suspicious JA3 fingerprints with low extension count, few ciphers, and unusual curve selections. RandomForest captures these feature interactions well.
- **Features engineered**:
  - `extensions_count` — number of TLS extensions (malware often has 0-2)
  - `ciphers_count` — number of cipher suites supported
  - `curves_count` — number of elliptic curves supported
  - `min_size` — minimum TLS record size
  - `median_size` — median TLS record size
- **Training/validation approach**:
  - Dataset: 200 benign JA3 samples (Chrome/Firefox) + 200 malware MTA patterns (public trace analysis)
  - Train/test split: 80/20
  - Metrics: `test_auc = 1.0, accuracy = 1.0` (tn=41, fp=0, fn=0, tp=39)
  - **Caveat**: AUC and accuracy evaluated on synthetic derived dataset; real malware JA3 patterns may differ. See `data/models/evaluation.json` and `data/DATASETS.md`.

---

## 5. Port Scan Detector — Rule-based Fan-out Analysis

- **Model/technique**: Rule-based detector tracking unique destination ports and unique destination hosts per source IP. Flagged when `unique_ports > 20` or `unique_hosts > 15`.
- **Why it fits**: Port scans exhibit high fan-out across many destination ports or hosts in a short time. The rule-based approach provides interpretable thresholds without needing machine learning.
- **Features engineered**:
  - `unique_dst_ports` — count of distinct destination ports observed
  - `unique_dst_hosts` — count of distinct destination IPs observed (hardcoded to 1 for single-target scans)
  - `syn_to_ack_ratio` — SYN/ACK ratio (typically > 5:1 for scans)
- **Training/validation approach**:
  - Dataset: Scapy-generated lab traffic with 200–2000 unique ports per scan flow + CIC-IDS-2017 distilled port fan-out statistics
  - No train/test split (thresholds tuned on validation set)
  - Metrics: `accuracy = 1.0` (tp=100, tn=100, fp=0, fn=0, threshold: unique_ports > 20 or unique_hosts > 15)
  - **Caveat**: Accuracy evaluated on synthetic derived dataset with fixed port ranges; real scans may vary. See `data/models/evaluation.json` and `data/DATASETS.md`.

---

## 6. Exfiltration Detector — IsolationForest

- **Model/technique**: `IsolationForest` (scikit-learn) trained on byte-volume features. Flagged when outbound byte ratio exceeds threshold and anomalous byte patterns are detected.
- **Why it fits**: Exfiltration moves large volumes of data out of the network. The feature `byte_ratio_outbound` = total outbound bytes / (10 MB) naturally captures large transfers that exceed organizational policies.
- **Features engineered**:
  - `byte_ratio_outbound` — outbound bytes / (10 * 1024 * 1024) — ratio against 10 MB baseline
  - `total_bytes_transferred` — total bytes moved in the flow
  - `avg_packet_size` — average packet size (large packets = bulk transfer)
  - `outbound_inbound_ratio` — ratio of outbound to inbound bytes (exfil is heavily outbound-biased)
- **Training/validation approach**:
  - Dataset: Scapy-generated lab traffic (500KB–50MB outbound transfers) + CIC-IDS-2017 distilled byte ratio statistics
  - Train/test split: 80/20
  - Metrics: `test_auc = 0.9933` (on synthetic derived hold-out set)
  - **Caveat**: AUC evaluated on synthetic derived dataset; real exfiltration volumes and patterns may differ. See `data/models/evaluation.json` and `data/DATASETS.md`.

---

## Dataset & Evaluation Summary

| Detector | Training Data | Real or Synthetic | Evaluation on |
|---|---|---|---|
| DDoS | CIC-derived stats + IsolationForest | Synthetic derived | 80/20 split, contamination 0.05 |
| C2 Beacon | Scapy lab + CTU-13 stats | Synthetic derived | Periodic vs jitter threshold |
| DGA | Tranco benign + DGArchive synthetic | Mixed (real benign, synthetic malicious) | Hold-out 20% synthetic derived |
| TLS Malware | JA3 benign + MTA patterns | Synthetic derived | RandomForest 80/20 |
| Port Scan | CIC-derived port stats | Synthetic derived | Rule threshold validation |
| Exfiltration | CIC-derived byte ratios | Synthetic derived | IsolationForest contamination 0.05 |

**All detectors are passive** — they analyze observed metadata; they do not generate attack traffic or payload decryption.

**Reproducibility**:
- Training script: `backend/cybersentinel-backend/scripts/train_all.py` (deterministic seed 42)
- Evaluation: `data/models/evaluation.json` and `backend/cybersentinel-backend/app/models/artifacts/evaluation.json`
- Lab traffic generation: `scripts/generate_lab_traffic.py` (Scapy-based, seed 42)

**Citation**: If you use Threx AI models, cite:
- Threx AI (2026), passive threat detection, https://github.com/threx-ai
- See `data/DATASETS.md` for full dataset attribution