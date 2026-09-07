# CyberSentinel Backend - Architecture

## System Architecture Diagram

```mermaid
graph TD
    %% Ingest Layer
    subgraph INGEST["Ingest Layer (Read-Only)"]
        direction TB
        PCAP[PCAP Files / tcpdump] -->|passive| PREAD[PcapReader / Scapy]
        INTERFACE[Network Interface] -->|sniff()| PREAD
        PREAD -->|PacketInfo| FLOWB[Flow Builder]
        FLOWB -->|Flow State| FLOWT[Flow Table (Redis / In-Memory)]
    end

    %% Feature Extraction
    subgraph FEATURES["Feature Extraction Layer"]
        direction TB
        FLOWB -->|Flow metadata| DDOS_F[DDoS Features]
        FLOWB -->|Flow metadata| BEAKON_F[Beacon Features]
        FLOWB -->|Flow metadata| DGA_F[DGA Features]
        FLOWB -->|TLS ClientHello| TLS_F[TLS Features]
        FLOWB -->|Flow metadata| SCAN_F[Scan Features]
        FLOWB -->|Flow metadata| EXFIL_F[Exfiltration Features]
    end

    %% ML Models
    subgraph MODELS["ML Model Layer"]
        direction TB
        DDOS_F -->|Isolation Forest| DDOS_D[DDoS Detector]
        BEAKON_F -->|FFT + CV| BEAKON_D[Beacon Detector]
        DGA_F -->|LightGBM| DGA_C[DGA Classifier]
        TLS_F -->|Random Forest| TLS_C[TLS Malware Classifier]
        SCAN_F -->|Statistical| SCAN_D[Scan Detector]
        EXFIL_F -->|Isolation Forest| EXFIL_D[Exfil Detector]
    end

    %% Inference Engine
    subgraph INFERENCE["Inference Engine"]
        direction TB
        IE[InferenceEngine]:::inference
        IE -->|asyncio.gather| DDOS_D
        IE -->|asyncio.gather| BEAKON_D
        IE -->|asyncio.gather| DGA_C
        IE -->|asyncio.gather| TLS_C
        IE -->|asyncio.gather| SCAN_D
        IE -->|asyncio.gather| EXFIL_D
    end

    %% Alert Management
    subgraph ALERTS["Alert Management Layer"]
        direction TB
        AE[AlertManager]:::alerts
        AE -->|deduplicate| AGG[Aggregator]
        AE -->|severity assign| SD[Severity Decider]
        DDOS_D & BEAKON_D & DGA_C & TLS_C & SCAN_D & EXFIL_D -->|Alert dicts| AE
        AE -->|Alert Pydantic| BD[Alert Broadcaster]
    end

    %% Delivery
    subgraph DELIVERY["Delivery Layer"]
        direction TB
        BD -->|WebSocket| WS_CLIENT[React Frontend]
        BD -->|DB Persist| PSTORE[PostgreSQL]
        BD -->|Prometheus Counter| PROM[/metrics Endpoint]
    end

    style INGEST fill:#e3f2fd,stroke:#1976d2,stroke-width:2px
    style FEATURES fill:#e8f5e9,stroke:#388e3c,stroke-width:2px
    style MODELS fill:#fff3e0,stroke:#f6e05e,stroke-width:2px
    style INFERENCE fill:#ffeb3b,stroke:#fbc02d,stroke-width:2px
    style ALERTS fill:#ffcdd2,stroke:#b71c1c,stroke-width:2px
    style DELIVERY fill#e1f5fe,stroke:#01579b,stroke-width:2px
```

## Component Diagram

```mermaid
graph LR
    %% Main Entry
    U[React Frontend] -->|REST/WS| API[FastAPI App]
    
    %% API Routes
    API -->|routes| THREATS[/api/threats]
    API -->|routes| TRAFFIC[/api/traffic]
    API -->|routes| DNS[/api/dns]
    API -->|routes| TLS[/api/tls]
    API -->|routes| RECON[/api/recon]
    API -->|routes| EXFIL[/api/exfil]
    API -->|routes| SYSTEM[/api/system]
    API -->|routes| REPORTS[/api/reports]
    API -->|routes| WS[/ws/alerts, /ws/metrics]
    
    %% Core Pipeline
    API -->|inject| INGEST[Ingest Pipeline]
    INGEST -->|read| PCAP_READER[PcapReader / LiveSniffer]
    INGEST -->|flow| FLOW_BUILDER[FlowBuilder / FlowTable]
    INGEST -->|metrics| METRICS[FlowMetrics]
    
    INGEST -->|parallel| INFERENCE[InferenceEngine]
    INFERENCE -->|detector| DDOS[DDoSDetector]
    INFERENCE -->|detector| BEAKON[BeaconDetector]
    INFERENCE -->|detector| DGA[DGAClassifier]
    INFERENCE -->|detector| TLS[TMClassifier]
    INFERENCE -->|detector| SCAN[ScanDetector]
    INFERENCE -->|detector| EXFIL[ExfilDetector]
    
    INFERENCE -->|alerts| ALERT_MGR[AlertManager]
    ALERT_MGR -->|broadcast| BROADCASTER[AlertBroadcaster]
    ALERT_MGR -->|persist| STORAGE[AlertStorage]
    
    %% Metrics flow
    METRICS -->|Prometheus| PROMETHEUS[/metrics endpoint]
    
    %% Model artifacts
    MODELS[/app/models/artifacts/] -.->|loads| DDOS
    MODELS -.->|loads| BEAKON
    MODELS -.->|loads| DGA
    MODELS -.->|loads| TLS
    MODELS -.->|loads| SCAN
    MODELS -.->|loads| EXFIL
```

## Data Flow

```
1. Ingest Phase
   ├─ PCAP reader or live sniffer passively captures packets
   ├─ L2/L3/L4 headers extracted (never payload content)
   ├─ 5-tuple flow builder groups packets (src_ip, src_port, dst_ip, dst_port, protocol)
   ├─ Flow state tracked with 60s TTL expiry
   └─ Metrics collected: flows/sec, packets/sec, bytes/sec

2. Feature Extraction Phase
   ├─ 7 extractors run in parallel on each flow:
   │  ├─ DDoS: entropy, SYN ratio, UDP amp ratio, IF features
   │  ├─ Beacon: CV, FFT periodicity, jitter, destination rarity
   │  ├─ DGA: entropy, n-gram scores, consonant/vowel, digit ratio, length
   │  ├─ TLS: JA3/JA4 fingerprints, packet size sequence
   │  ├─ Scan: fan-out counts, horizontal vs vertical classification
   │  ├─ Exfil: byte ratios, duration, byte skew, duration stats
   │  └─ All features are metadata-only, no payload decryption
   └─ Features flow to Inference Engine

3. Inference Phase
   ├─ InferenceEngine runs all 6 detectors via asyncio.gather()
   ├─ Each detector may raise an Alert dict/None
   ├─ Alerts merged, deduplicated, severity assigned
   ├─ Final confidence = weighted combo of rule + ML scores
   └─ Deduplication: same threat_class + src/dst + 5-min window

4. Delivery Phase
   ├─ AlertManager sends to AlertBroadcaster
   ├─ WebSocket broadcast to connected React clients
   ├─ DB persistence to PostgreSQL via AlertStorage
   ├─ Prometheus counters incremented
   └─ /api/threats endpoint returns paginated results
```

## Key Design Decisions

### Read-Only Ingest Design
- All packet parsing uses Scapy's `PcapReader` or `sniff()` with BPF filters
- No outbound socket connections from the ingest pipeline
- Flow keys computed from observed 5-tuples only (no active probing)
- TLS metadata (JA3/JA4) extracted from ClientHello fields only
- DNS analysis from query names and record types, never content

### Streaming Pipeline
- `asyncio.gather()` runs all 6 detectors in parallel per flow
- Bounded latency: each detector has configurable thresholds
- Alert deduplication window: 5 minutes (same threat + same flow)
- Flow table TTL: 60 seconds automatic expiry
- Metrics: 1-second reporting interval via Prometheus

### Model Architecture
- **DDoS**: Rule-based thresholds (SYN/ACK > 10:1, amp > 20:1) + Isolation Forest
- **Beacon**: FFT periodicity + CV < 0.1 threshold + confidence product
- **DGA**: LightGBM on lexical features (entropy, n-grams, CV, digit ratio)
- **TLS**: Random Forest on JA3 + packet size sequence features
- **Scan**: Statistical fan-out with sliding window (60s)
- **Exfil**: Isolation Forest + rule-based ratio > 10:1 + volume > 10MB

### State Management
- **Hot state**: Redis for flow tables (TTL-based auto-expiry)
- **Persistent**: PostgreSQL for alerts and flow records
- **Cache**: In-memory dict for MVP (replaceable with Redis in production)
- **Alert deduplication**: Based on threat_class + source_ip + destination_ip + protocol

## Operational Requirements

### Hardware (for 10,000 flows/sec target)
- 4-core CPU (minimum)
- 8GB RAM (recommended)
- 50GB+ storage for PCAP archives
- Network interface in promiscuous mode (for live capture)

### Software Dependencies
- Python 3.11+
- FastAPI, uvicorn
- Scapy for PCAP parsing
- scikit-learn, LightGBM for ML
- Redis 7+ (optional, can use in-memory dict)
- PostgreSQL 13+ (optional, SQLite for MVP)
- aiokafka (planned, currently using asyncio.Queue)

### Deployment
- Docker + docker-compose (3 services: backend, redis, postgres)
- 4 uvicorn workers for production
- Health checks: /health (liveness), /metrics (Prometheus)
- CORS: http://localhost:5173 (Vite dev server) + configurable origins

### Monitoring
- Prometheus /metrics endpoint
- /health liveness probe
- Alert counts by class and severity
- Throughput: flows/sec, packets/sec, bytes/sec
- Inference latency p50/p99