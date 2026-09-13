# Threx AI — Passive Cyber Threat Intelligence Platform

AI-powered **passive** SOC dashboard (React 19 + TypeScript) + FastAPI backend with 6 ML detectors. Designed for critical-infrastructure networks where telemetry is one-way (data diode).

> **Passive guarantee:** no packets are ever sent back, no payload decryption. See `backend/cybersentinel-backend/README.md` and `data/DATASETS.md`.

## Architecture at a glance
- **Frontend** `frontend/` — Vite 8, React 19, Tailwind v4, Recharts, react-router-dom 7. 12 routes, PWA-ready.
- **Backend** `backend/cybersentinel-backend/app/` — FastAPI, Scapy, LightGBM, scikit-learn, Redis, SQLite (dev) / Postgres (prod), WebSocket.
- **Data** `data/` — public datasets attribution, synthetic-derived training data, PCAP schemas, JA3 fingerprints.
- **Models** `backend/cybersentinel-backend/app/models/artifacts/` — 4 trained artifacts + `evaluation.json`.

## Quickstart — Local (without Docker)

### 1. Backend
```bash
cd backend/cybersentinel-backend
python3 -m venv .venv && source .venv/bin/activate  # optional
pip install -r requirements.txt               # installs fastapi, uvicorn, lightgbm, scikit-learn, scipy ...
# optional: training is already done (artifacts committed), but to retrain:
brew install libomp   # macOS only, required for lightgbm
python scripts/train_all.py

cp .env.example .env   # edit CYBERSENTINEL_CORS_ORIGINS if needed
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
# verify
curl http://localhost:8000/health | jq
curl http://localhost:8000/threats/?limit=2 | jq
```

### 2. Frontend
```bash
cd frontend
npm install
cp .env.example .env   # VITE_API_URL=http://localhost:8000 by default
npm run dev            # http://localhost:5173
npm run build && npm run preview  # production preview on http://localhost:4173
```

The dashboard auto-detects the backend and shows a single unified status indicator:
- **SIMULATION** (yellow) — backend unreachable, mock data
- **BACKEND SEEDED** (green) — backend live, DB-persisted alerts
- **PCAP REPLAY** (green) — replaying captured flow records
- **LIVE INGEST** (blue) — `CYBERSENTINEL_LIVE_INTERFACE` set, passive capture active
- **LAB TRAFFIC** (cyan) — lab-generated flow records in pipeline

## Quickstart — Docker (full stack)
```bash
# from repo root
cp .env.example .env
cp backend/cybersentinel-backend/.env.example backend/cybersentinel-backend/.env
cp frontend/.env.example frontend/.env
# choose strong passwords in .env (POSTGRES_PASSWORD, etc.)
docker compose up --build -d
# wait ~20s for healthchecks
curl http://localhost:8000/health
curl http://localhost:80/   # frontend via nginx
docker compose logs -f backend
```

Services:
- `threx-backend` :8000 (API) + :9090 (metrics)
- `threx-frontend` :80 (nginx SPA)
- `threx-redis` :6379
- `threx-postgres` :5432 (pg_data volume)

## Configuration

All env vars are documented in:
- `backend/cybersentinel-backend/.env.example`
- `frontend/.env.example`
- `./.env.example` (compose root)

Key vars:

| Var | Default | Purpose |
|-----|---------|---------|
| `CYBERSENTINEL_ENV` | `development` | `production` enables HSTS etc. |
| `CYBERSENTINEL_CORS_ORIGINS` | `http://localhost:5173` | comma-separated allowed origins |
| `CYBERSENTINEL_API_KEY` | _(empty)_ | if set, clients must send `X-API-Key` |
| `CYBERSENTINEL_RATE_LIMIT_PER_MINUTE` | `120` | per-IP sliding window |
| `CYBERSENTINEL_DB_PATH` | `data/alerts.db` | SQLite fallback path |
| `CYBERSENTINEL_POSTGRES_DSN` | `postgresql://...` | Postgres DSN (docker compose overrides) |
| `CYBERSENTINEL_LIVE_INTERFACE` | _(empty)_ | e.g. `eth0` to enable passive sniffing |
| `VITE_API_URL` | `http://localhost:8000` | frontend → backend |

## Routes

Frontend (all verified):

 `/` , `/overview` — command center + metrics + donut/threat map
 `/threats` , `/threats/:id` — table + investigation (evidence, flow viz, notes, exports)
 `/traffic` , `/dns` , `/tls` , `/recon` , `/exfil` — analytics per threat class
 `/alerts` — AlertCenter bulk actions
 `/reports` — generator (type/format) → POST `/reports/generate` → JSON/CSV download
 `/ai-engine` — model cards, pipeline, latency
 `/system` — health, resources, diode status
 `*` — NotFound

Backend OpenAPI at `http://localhost:8000/docs`:

```
GET  /health, /health/ready, /health/live, /api/health …
GET  /metrics, /api/metrics  (Prometheus)
GET  /threats, /threats/{id}
GET  /traffic/stats, /top-talkers, /protocols
GET  /dns/dga, /dns/tunneling
GET  /tls/fingerprints, /tls/malware
GET  /recon/scans
GET  /exfil/anomalies
GET  /system/status, /system/throughput
POST /reports/generate  (ReportConfig {format, threat_class, severity, limit})
WS   /ws/alerts, /ws/metrics
GET  /
```

## Data & Models

See `data/DATASETS.md` for sources/licenses and `data/models/evaluation.json` for actual metrics. See `MODEL_DOCUMENTATION.md` for full model documentation per detector.

**Training:** deterministic seed 42, 80/20 stratified split where applicable.

```
DGA (LightGBM):        train AUC 0.9991, test AUC 1.0   — 1000 Tranco benign + 5000 DGArchive-derived malicious
TLS malware (RF):      test AUC 1.0, Acc 1.0            — 200 benign + 200 malware JA3/packet-size synthetic
DDoS (IsolationForest):test AUC 0.9967                  — 300 benign + 300 attack flow rates
Exfil (IsolationForest): test AUC 0.9933
C2 beacon (FFT+CV):    Acc 1.0 (threshold cv<0.1)
Port scan (stat):      Acc 1.0 (ports>20 or hosts>15)
```

Artifacts are committed under `backend/cybersentinel-backend/app/models/artifacts/` and auto-loaded on startup. If missing, the backend trains on first boot (takes ~10s for DGA).

## Measured Throughput

Tested on 180 lab flows (mixed threat classes), scapy-generated:

```
Sustained peak:    88.6 flows/sec
p50 latency:       12.93 ms
p95 latency:       12.93 ms
p99 latency:       13.95 ms
Zero drops:        YES
Return path:       NONE (read-only pipeline)
```

Lab traffic generated by `scripts/generate_lab_traffic.py` (361 flows across 9 files).
See `data/throughput_measurement.json` for full results.

## Lab Traffic Generation

```bash
python3 scripts/generate_lab_traffic.py   # generates data/pcaps/attacks/*.json + mixed/lab_mixed.json
```

Produces real flow records with characteristics matching real attack tools:
- DDoS SYN flood (SYN/ACK ratio 9:1, 5000-50000 packets)
- Slowloris (120-600s duration, tiny packets)
- DNS tunneling (high query frequency, TXT records)
- DGA domains (5 families: Nymaim, Matsnu, Suppobox, Gozi, CryptoLocker)
- C2 beaconing (60s interval, 5% jitter)
- Port scanning (200-2000 unique ports)
- TLS malware (suspicious JA3, zero extensions)
- Exfiltration (500KB-50MB outbound)

## Production build

```bash
# frontend
cd frontend && npm run build   # outputs dist/, served by nginx in Docker
# backend
cd backend/cybersentinel-backend
pip install -r requirements.txt
pytest -q   # 52 passed
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

Health probes used by Docker/K8s:

```
HEALTHCHECK curl -f http://localhost:8000/health
# readiness: /health/ready   liveness: /health/live
# frontend: wget -qO- http://localhost/
```

## Security hardening (already applied)

- CORS allowlist (explicit origins, no wildcard when credentials)
- Security headers: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, HSTS in production, `Permissions-Policy`
- `X-Request-Id` echo
- Rate limiting (per-IP, per-minute sliding window, 429)
- Optional `X-API-Key` enforcement
- Input validation via Pydantic (6 evidence limit, protocol/severity enums, Alert schema)
- Global exception handler (no stack leak)
- Non-root nginx, minimal base images, `npm ci`, `.env` not committed

## Deployment steps (checklist)

1. Clone repo, copy `.env.example` → `.env` in three places, set strong `POSTGRES_PASSWORD` and `CYBERSENTINEL_API_KEY` if desired.
2. Frontend: `npm ci && npm run build` (or `docker compose build frontend`).
3. Backend: `pip install -r requirements.txt` and ensure `app/models/artifacts/*.joblib` exist (`python scripts/train_all.py` if not).
4. Start: `docker compose up -d` (or systemd/uvicorn + nginx). Verify `curl /health` returns 200.
5. Point DNS/FQDN to frontend, terminate TLS at load balancer (HSTS header already sent when `CYBERSENTINEL_ENV=production`).
6. Configure log shipping (uvicorn access logs → stdout, picked up by compose `json-file` driver).
7. Backups: mount `pg_data` and `data/alerts.db` to persistent volumes.

## Troubleshooting

- `libomp` missing on macOS: `brew install libomp`
- `ModuleNotFoundError: cybersentinel_backend` in tests: already fixed (imports are `from app...`, run with `pytest` from `backend/cybersentinel-backend`)
- CORS blocked: ensure `CYBERSENTINEL_CORS_ORIGINS` includes your frontend origin
- DB empty after restart: SQLite file is `backend/cybersentinel-backend/data/alerts.db`; postgres is `pg_data` volume — both re-seeded only if empty

## License / Attribution

See `data/DATASETS.md` for Tranco, DGArchive, CIC-IDS, CTU-13, JA3/MTA licenses. Internal code is proprietary for this demo; dataset artifacts follow their upstream licenses (CC0/BSD/research-use).
