# Threx AI — Datasets & Attribution

This document records every dataset used for training, evaluation, and demonstration.
No dataset content is fabricated without attribution. Synthetic data is explicitly labeled as SYNTHETIC DERIVED.

## Principles
- **Passive only**: no live attack traffic collection, no payload decryption.
- **Public data only**: all training data comes from public, legitimately published datasets.
- **Attribution required**: licenses and sources recorded below.
- **Documentation IPs/domains**: sample alerts use RFC 5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and RFC 1918 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). No real victim IPs.

## Datasets Used

### 1. Benign Domains — Tranco Top 1M / Alexa Top 1M (subset)
- **Source**: Tranco list (https://tranco-list.eu/) — research-oriented top sites, CC0. Original Alexa Top 1M is deprecated; Tranco is the community successor.
- **License**: Tranco data is public domain (CC0) aggregated from Alexa, Umbrella, Majestic.
- **Used for**: DGA benign class (legitimate domains).
- **Files**: `data/domains/benign/tranco_top_1000.txt` (1000 domains, sampled from Tranco top ranking), `backend/cybersentinel-backend/data/models/alexa_top_1m.txt` (synthetic benign counterpart for offline training).
- **Processing**: lowercased, deduplicated, length 3–63 labels, LDH rule valid.

### 2. Malicious DGA Domains — DGArchive (subset/synthetic derived)
- **Source**: DGArchive (https://dgarchive.caad.fkie.fraunhofer.de/) — Fraunhofer FKIE, APT/DGA collection.
- **License**: DGArchive is for research use — cited via academic fair use, no redistribution of full archive. We provide a **synthetic derived set** that reproduces statistical properties (entropy >3.5, length 8–20, mixed alphanumeric) rather than copying private DGA strings.
- **Used for**: DGA malicious class.
- **Files**: `data/domains/malicious/dgarchive_synthetic_5000.txt` (5000 synthetic DGA-like domains seeded 42, entropy-filtered), `backend/cybersentinel-backend/data/models/dgarchive_samples.txt`.
- **Note**: Evaluation metrics reported are on this synthetic derived set. Replace with the official DGArchive export for production retraining.

### 3. Network Flows — CIC-IDS-2017 / CIC-IDS-2018 / CSE-CIC-IDS2018
- **Source**: Canadian Institute for Cybersecurity (CIC), University of New Brunswick (https://www.unb.ca/cic/datasets/ids-2017.html, https://www.unb.ca/cic/datasets/ids-2018.html)
- **License**: Public dataset for research (permissive, citation required: Sharafaldin et al., CIC).
- **Used for**: DDoS, Port Scan, and Exfiltration flow statistics — packet rate, byte rate, duration, port fan-out, byte ratios. We distilled **flow-summary CSV** characteristics into detector thresholds and IsolationForest synthetic training data (not raw PCAP).
- **Files**: `data/schemas/cic_flow_schema.json`, `data/labels/cic_label_map.json`, `backend/cybersentinel-backend/data/pcaps/README.md` explains how to ingest CIC PCAPs if downloaded separately.
- **How to download full PCAPs**: `scripts/download_cic.sh` (provided) fetches from UNB site; requires manual acceptance of terms.

### 4. TLS / JA3 — JA3 database + Malware-Traffic-Analysis.net
- **Source**: JA3 method by Salesforce (John Althouse) — https://github.com/salesforce/ja3 (BSD-3). Malware TLS samples from https://malware-traffic-analysis.net/ (Brad Duncan).
- **License**: JA3 code BSD-3; MTA pcaps are public for research.
- **Used for**: TLS/JA3 malware detector — cipher/extension/curve counts + packet-size sequences.
- **Files**: `data/ja_fingerprints/ja3_benign_samples.json` (100 benign fingerprints, e.g., Chrome/Firefox), `data/ja_fingerprints/ja3_malware_samples.json` (100 malware fingerprints, e.g., TrickBot, Emotet patterns), `data/schemas/ja_schema.json`.
- **Note**: JA3 strings are hashes of ClientHello metadata, not payload.

### 5. C2 Beaconing — CTU-13 / Stratosphere IPS
- **Source**: CTU-13 dataset (Stratosphere Lab, CTU Prague) — https://www.stratosphereips.org/datasets-ctu13
- **License**: CC BY-NC-SA, research use.
- **Used for**: Beacon detector validation — periodic timing (FFT) and inter-arrival CV.
- **Files**: `data/labels/ctu13_beacon_stats.json` (statistical summary: periodicity, CV, dominant period).

### 6. DNS Tunneling — DNS tunneling tool captures (iodine, dnscat2) + Cisco Umbrella
- **Source**: Synthetic captures from iodine/dnscat2 lab runs + Cisco Umbrella Top 1M (benign).
- **Used for**: DNS tunneling detector — query frequency, TXT volume, subdomain entropy.
- **Files**: Referenced in `data/schemas/dns_schema.json`.

## Synthetic vs Real
| Detector | Training data | Real or Synthetic | Evaluation on |
|---|---|---|---|
| DGA | Tranco benign (real subset) + DGArchive synthetic derived (statistical replica) | Mixed (real benign, synthetic malicious) | Hold-out 20% synthetic derived — metrics recorded in `data/models/evaluation.json` |
| DDoS | CIC-derived statistics (synthetic flows with CIC-like rates) + IsolationForest | Synthetic derived from public stats | 80/20 split, contamination 0.05 |
| C2 Beacon | CTU-13 timing stats, synthetic periodic traces | Synthetic derived | Periodic vs jitter threshold |
| TLS Malware | JA3 benign (real browser) + malware (public MTA patterns) — synthetic sequences | Synthetic derived | RandomForest 80/20 |
| Port Scan | CIC-derived port fan-out stats | Synthetic derived | Rule threshold validation |
| Exfiltration | CIC-derived byte ratios + synthetic outbound bursts | Synthetic derived | IsolationForest contamination 0.05 |

All detectors are **passive** — they analyze observed metadata; they do not generate attack traffic.

### 7. Lab Traffic — Scapy-generated flow records (real tool characteristics)
- **Source**: Generated by `scripts/generate_lab_traffic.py` using Scapy. Each traffic class replicates the packet-level characteristics of real attack tools:
  - **Benign TCP**: Normal web/SSH/DNS traffic — 10-200 packets/flow, 60-1500 byte packets, 0.5-30s duration
  - **DDoS SYN Flood**: SYN-only packets, 9:1 SYN/ACK ratio, 5000-50000 packets/flow, 5-60s duration (mimics hping3 `--flood -S`)
  - **Slowloris**: Slow HTTP connections, 120-600s duration, tiny packets, high avg_packet_interval (mimics slowloris.py behavior)
  - **DNS Tunneling**: High query frequency, TXT queries, high subdomain entropy (mimics iodine/dnscat2 patterns)
  - **DGA Queries**: 5 DGA families (Nymaim, Matsnu, Suppobox, Gozi, CryptoLocker) — algorithmically generated domains with entropy >3.5, digit ratios, consonant-vowel ratios
  - **C2 Beaconing**: 60-second beacon interval, 5% jitter, periodic TCP connections to port 443
  - **Port Scan**: 200-2000 unique destination ports per flow, SYN+RST pattern
  - **TLS Malware**: Suspicious JA3 fingerprints, zero/low extension+curve+cipher counts
  - **Exfiltration**: Large outbound transfers, 500KB-50MB per flow
- **License**: Generated for this project, RFC 5737 documentation IPs only.
- **Used for**: Pipeline demonstration, streaming verification, throughput measurement, schema validation.
- **Files**: `data/pcaps/attacks/*.json` (9 files), `data/pcaps/benign/benign_tcp.json`, `data/pcaps/mixed/lab_mixed.json` (180 flows mixed)
- **How to regenerate**: `python3 scripts/generate_lab_traffic.py`

## Reproducibility
- Training script: `backend/cybersentinel-backend/scripts/train_all.py` (deterministic seed 42).
- Evaluation: `data/models/evaluation.json` and `backend/cybersentinel-backend/app/models/artifacts/evaluation.json`.
- To retrain on official downloads, replace the `*_synthetic_*` files with full exports and rerun `train_all.py`.

## Citation Template
If you use Threx AI datasets, cite:
- Threx AI (2026), passive threat detection, https://github.com/threx-ai
- Tranco (Le Pochat et al., IMC 2019)
- DGArchive (Plohmann et al., DIMVA 2016)
- CIC-IDS-2017/2018 (Sharafaldin et al.)
- CTU-13 (Garcia et al.)
- JA3 (Althouse et al., Salesforce)

## Contact
For dataset questions, open an issue with label `dataset`.
