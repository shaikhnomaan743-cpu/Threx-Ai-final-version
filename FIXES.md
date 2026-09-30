# Fixes Applied

Everything below was reproduced first (install / build / boot / test), then fixed,
then re-verified. Final state: `tsc -b` clean, `vite build` succeeds,
52/52 backend tests pass, all 10 API endpoints return 200, all 23 pages render.

---

## 1. Frontend build was dead — 37 TypeScript errors

**Cause:** `frontend/src/lib/utils.ts` was missing five exports that 37 files
import. `cn` alone was imported by 24 components, so nothing compiled.

**Fix:** implemented the missing exports in `src/lib/utils.ts`:

| Export | Notes |
|---|---|
| `cn` | `clsx` + `tailwind-merge`, so later Tailwind utilities win |
| `formatNumber` | compact form — `2350000` -> `2.35M` |
| `formatBits` | includes its own unit suffix — `2350000` -> `2.35 Mbps` |
| `formatDuration` | **takes milliseconds** |
| `generateId` | short collision-resistant id for mock records |

`formatDuration` units were verified against the call sites: pipeline latency
(`0.4`) and scan duration (`300000`) are *both* milliseconds in `mockData.ts`,
so one implementation handles both correctly.

## 2. Backend `pip install` was dead

`requirements.txt` pinned `scapy>=2023.12.0`. No such version exists (scapy tops
out at 2.7.x), so pip aborted and installed **nothing**.

- `scapy>=2023.12.0` -> `scapy>=2.6.0`   (both requirements files)
- `httpx[extra]>=0.27.0` -> `httpx>=0.27.0`   — `extra` is not a real httpx extra
- `pytest-rush>=2.8.0` -> `pytest-xdist>=3.5.0`   — `pytest-rush` is not on PyPI
- removed `tracemalloc` — stdlib, cannot be pip-installed

## 3. `docker compose up` was dead

All five paths pointed at `./backend/cybersentinel-backend`, but the directory
was `backend/backend`.

**Fix:** renamed `backend/backend` -> `backend/cybersentinel-backend` and updated
`docker-compose.yml`. The folder was the wrong thing, not the docs — ~20
references in `README.md` and `data/DATASETS.md` already said
`cybersentinel-backend`.

## 4. Silent CORS failure on 127.0.0.1

`app/main.py` allowed only `http://localhost:5173`. Browsers treat
`127.0.0.1` and `localhost` as different origins, so opening the UI at the
127.0.0.1 address — exactly what `vite --host` prints — made **every API call
fail with no visible error**.

**Fix:** both spellings for all three dev ports (5173 dev, 4173 preview,
3000 nginx/docker). Verified unknown origins still receive no CORS header.

## 5. Pydantic V1 style — would hard-break on Pydantic V3

- `app/alerts/schema.py`: `@validator` -> `@field_validator` (+ `@classmethod`,
  `pre=True` -> `mode="before"`)
- `app/config.py`: class-based `Config` -> `SettingsConfigDict`

Pydantic deprecation warnings: 4 -> 0.

## 6. Cleanup

- Removed 42 unused imports (lint warnings 91 -> 49; the rest are unused
  locals/params and React hook advisories, none breaking).
- `services/searchIndex.ts`: replaced a side-effecting
  `this.ips.get(ip)?.add(id) || this.ips.set(...)` expression with an explicit
  `indexIp()` helper.
- Deleted `frontend/src/{components,pages,lib,hooks}` — an empty directory
  literally named with the braces, created by a `mkdir -p` run in a shell
  without brace expansion.
- Removed `__pycache__`, `.pytest_cache`, `.DS_Store`.

---

## Still outstanding (design decision, not a bug)

**You have two parallel page sets, and one is unroutable dead code.**

`App.tsx` routes to the short-named pages, which use `lib/api` and **default**
exports:
`Overview, Threats, Traffic, DNS, TLS, Recon, Exfil, Alerts, Reports, AIEngine, System`

A second, more built-out set uses `services/apiClient` and **named** exports and
is reachable from nowhere:
`DNSAnalytics, TLSAnalytics, Reconnaissance, Exfiltration, AlertCenter,
AIDetectionEngine, SystemStatus, ThreatInvestigation, TrafficAnalytics`

Same split in the layouts: `components/Layout` is live;
`components/layout/{MainLayout,Sidebar,TopBar}` is not.

Most of the missing-utils errors in item 1 came from the *unrouted* set — strong
evidence it has never been run. Nothing was deleted, since which set to ship is
your call. For the NTRO submission, pick one and cut the other: a reviewer
opening the repo will otherwise see two competing dashboards.

**Model artifacts:** the `.joblib` files were pickled with scikit-learn 1.9.0 and
emit `InconsistentVersionWarning` on load. Pin `scikit-learn` to the version you
trained with, or retrain via `scripts/train_all.py`.

---

## Run it

```bash
# backend
cd backend/cybersentinel-backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# frontend (separate terminal)
cd frontend
npm install
npm run dev          # http://localhost:5173
```

---

# Round 2 — blank pages when the backend is running

**Symptom:** Overview renders, but clicking Traffic Analytics / DNS / TLS /
Reconnaissance / Exfiltration goes blank. Backend logs are clean.

**Cause:** shape mismatch between the API and the pages. Every detection
endpoint returns a *flat array of alert records*:

```json
[ { "alert_id": "...", "threat_class": "dga", "confidence": 0.86,
    "source_ip": "...", "evidence": [ {"feature_name":"domain_entropy", ...} ] } ]
```

but the pages were written against *summary objects* — `fetchDNS()` was expected
to return `{ total, dga, tunnel, entropy, families[], samples[] }`. So
`d.samples.map(...)` ran against `undefined`, threw during render, and React
unmounted the tree — a blank screen with nothing in the backend log.

`/traffic/stats` mismatched too: it returns `total_flows` / `total_bytes`, while
`Traffic.tsx` reads `s.flows`, `s.bytes`, `s.avg_dur` and `s.protocols`.

This is why it only broke *with the backend up*. With it down, the `catch`
branch returned correctly-shaped mock data and every page worked.

**Fix:** `src/lib/api.ts` now adapts each response to the shape its page
renders. Real values are used wherever the backend supplies them:

| Page | Derived from |
|---|---|
| Traffic | `/traffic/stats` + protocol mix computed from `/threats?limit=500` |
| DNS | `/dns/dga` + `/dns/tunneling`; entropy averaged from `domain_entropy` evidence |
| TLS | `/tls/fingerprints`; `extensions_count` / `ciphers_count` from evidence |
| Recon | `/recon/scans`; `unique_dst_ports` / `unique_dst_hosts` from evidence |
| Exfil | `/exfil/anomalies`; `outbound_inbound_ratio`, `bytes_transferred` |

Each adapter still falls back to mock data if the endpoint is unreachable or
returns an unexpected shape, so the dashboard degrades instead of blanking.

**Two DNS labels changed to match the data that actually exists.** The backend
does not emit the queried domain name — only the flow's resolver target — so:

- "DGA Families Detected" -> **"Top DGA Sources"** (grouped by `source_ip`, real counts).
  It previously rendered `Math.random()` domain counts next to a hardcoded family list.
- Table column "Domain" -> **"Query Target"**, "Family" -> **"Severity"**.

If you want real family attribution and the queried name in that table, the
backend needs to include the domain string in the DGA alert (it currently sends
`raw_features: {}` for DGA). That is a backend change, not a UI one.

**Verified** by running the real fetchers against the live backend and replaying
each page's exact property accesses: 5/5 pass with the backend up
(`flows=1145`, `dga=81`, `tunnel=56`, `sessions=97`, `scans=81`, `exfil=68`),
and 5/5 pass with it stopped, on the fallback path.

---

# Round 3 — issues found by reviewing the dashboard screenshots

## Fixed

**1. Reports "generated" but never downloaded anything (reported).**
`Reports.tsx` was pure theatre: `setTimeout(() => setDone(true), 1500)`. No
fetch, no file. Meanwhile the backend already had a working
`GET /reports/generate`. Now wired up properly: real fetch, real Blob, real
browser download, with UI labels mapped to the backend vocabulary
(`Recon` -> `port_scan`, `C2 Beaconing` -> `c2_beacon`, etc.), plus an error
state instead of a permanent green tick.

**2. Confidence rendered as `0.08541076810820947%`.**
The backend sends confidence as 0-1; `Threats.tsx` printed `{a.confidence}%`
raw. Every row was wrong by 100x and unreadable.

**3. Threat-class filters could never match.**
The filter chips are `'DDoS'`, `'C2 Beaconing'`…; the backend sends `ddos`,
`c2_beacon`. Clicking any class filter silently returned nothing.

**4. Raw ISO timestamps** (`2026-09-13T14:09:40.199720Z`) wrapping in the table.

**5. `Block` column rendered a bare `#`.** The backend has no ledger, so
`block_height` was `undefined`. Now shows `—` rather than a fake block number.

2-5 are all fixed by one normaliser, `toAlert()` in `lib/api.ts`, applied at the
fetch boundary — so `Threats`, `ThreatDetail`, `Alerts` and `Overview` all get
correct data. `dns_tunnel` and `low` severity were added to the type unions;
the backend emits both and the UI had no representation for either.

**6. Command Center headline numbers were `Math.random()`.**
`useLiveData.ts` had `active_threats: 180 + Math.round(Math.random()*40)` and
`total_detections` incrementing randomly from zero. That is why the screenshot
showed **Total Detections: 1** while the threat distribution beside it summed to
500. The live threat feed was synthetic too, which is where impossible rows like
`DNS` traffic on ports `22 -> 3389` came from. Now polls real data every 5s via
`fetchMetrics()`, and only falls back to the simulator when the backend is down.

**7. Exfiltration ratio showed `3496570.0:1`.**
`compute_outbound_inbound_ratio` does `outbound / max(inbound, 1)`, and
`inbound_bytes` is never populated (it reads from `raw_features`, which is `{}`).
So the headline evidence feature was just the byte count wearing a ratio label.
Display now caps at `>1000`. **The underlying feature is still broken — see below.**

**8. TLS page read as "100% of sessions are malware".**
`TLS Sessions 97 / Malware Flagged 97` — because `/tls/fingerprints` only ever
returns flagged sessions. Relabelled `Flagged Sessions` / `High-Critical`.

**9. Backend leaked a FastAPI `FieldInfo` object into report JSON.**
`"type": {"example": {"value": null}, "include_in_schema": true, ...}`.
The GET alias called the POST handler directly without `report_type`, so the
parameter defaulted to the `Query(...)` object instead of `None`. Fixed at both
ends. Now returns `"type": "threat_summary"`.

## Verified

100 alerts fetched live: 0 confidences out of range (86%, 100%, 70%), 0 raw
snake_case classes, 0 un-normalised timestamps, all 7 classes present.
Metrics `total_detections=1000 active_threats=762`. Reports download in both
formats (JSON 35KB / CSV 19KB, 25 records) and class filtering works
(`Recon` -> 10 `port_scan` records). 52/52 backend tests still pass.

## NOT fixed — needs your decision

**`inbound_bytes` is never populated.** Exfiltration's primary evidence feature
is meaningless as a result. The display is now capped, but the *detector* still
scores on a degenerate value. This needs a fix in the flow builder, not the UI.

**`AI Detection Engine` page is hardcoded.** Every number on it — AUC, accuracy,
"Caught 112", "Total Caught 500" — comes from the `MODELS` constant in
`lib/utils.ts`, not from the running models. It does not reflect the live
system.

**Reported AUCs of 1.0000 will draw scrutiny.** DGA, TLS Malware, C2 and Recon
all claim perfect AUC on synthetic data. For an NTRO review this reads as data
leakage or a too-easy synthetic split rather than a strong result. Worth either
evaluating on harder data or stating the limitation explicitly.

**Service health is cosmetic.** The System page lists `threx-redis:6379` and
`threx-postgres:5432` as green when nothing is checking them — they show
connected even with no containers running.

**`Chain #3,680` / Ledger Anchoring.** The "tamper-evident chain of custody"
counter is a client-side number incremented at random; there is no ledger behind
it. Either implement the hashing or remove the claim before submitting.

---

# Round 4 — production crash on Railway: inference engine never loads

**Symptom:** frontend deploys fine; backend deploys and shows "Active", but
every single flow logs the same crash:

```
AttributeError: 'NoneType' object has no attribute 'analyze_flow'
```

**Root cause:** `python:3.11-slim` (the Dockerfile's base image) does not ship
`libgomp1`. LightGBM's compiled extension (`lib_lightgbm.so`) dynamically links
`libgomp.so.1` for its OpenMP threading — confirmed directly via `ldd`:

```
lib_lightgbm.so:
    libgomp.so.1 => /lib/x86_64-linux-gnu/libgomp.so.1
```

That file ships only in the separate `libgomp1` package. `build-essential` and
`gcc` do **not** pull it in as a dependency — they're compile-time tools, this
is a runtime shared library. So on the slim image, `import lightgbm` throws:

```
OSError: libgomp.so.1: cannot open shared object file: No such file or directory
```

This happens the moment `app.inference.engine` is imported (it imports
`app.models.dga_classifier`, which imports `lightgbm` at module level). That
import sits inside a bare `try/except Exception` in `main.py`'s startup
(`lifespan`), which was written to tolerate a *missing model file*, not a
*missing shared library*. It caught the `OSError` too, logged one line as a
`.warning()` with no traceback, and the global `inference_engine` variable —
declared `None` at module scope — was never reassigned. Every flow afterward
called `None.analyze_flow(...)`, forever, which is the traceback you saw.

**Why this never showed up locally or in earlier rounds:** this sandbox and
most dev machines run full (non-slim) Linux images, which already have
`libgomp1` installed as a transitive dependency of something else. Only a slim
container base exposes the gap. Docker isn't available in this sandbox, so I
verified the root cause directly — `ldd` on lightgbm's compiled library, then
confirmed `libgomp1` is a standalone package (`dpkg -S libgomp.so.1`) that
`gcc`/`build-essential` do not depend on.

## Fixed

**1. `Dockerfile`** — added `libgomp1` to the apt install list. This is the
actual fix.

**2. `main.py`** — changed `logger.warning(...)` to `logger.exception(...)` in
the inference-engine startup handler, so a future init failure prints the full
traceback instead of one opaque line. This is why the real cause was invisible
in your Railway logs — you only ever saw the *downstream* symptom in a
different module.

**3. `pipeline.py`** — added a guard: if `inference_engine` is `None`,
`process_flow` now logs one clear error ("startup init failed, skipping all
flows") and returns, instead of crashing with an identical traceback on every
flow indefinitely. This turns an infinite crash-log loop into one line, even
if some *other* future cause leaves the engine unset.

## Verified

- `ldd` confirms `lib_lightgbm.so` requires `libgomp.so.1`.
- `dpkg -S libgomp.so.1` confirms it belongs only to `libgomp1`, not
  `build-essential`/`gcc`.
- Full backend test suite still passes (52/52) after the `main.py` /
  `pipeline.py` edits.
- Docker isn't available in this sandbox, so the Dockerfile fix itself is
  **not build-verified end-to-end here** — verify by redeploying to Railway
  and confirming the deploy logs show `"DGA model loaded"` (or `"DGA model
  trained"`) instead of the `AttributeError` loop.

## Left alone, deliberately

I considered adding a `railway.json` to force the Dockerfile builder, but
didn't: your deploy is already "Active" and running `uvicorn --workers 4`
exactly as the Dockerfile's `CMD` specifies, which means Railway is almost
certainly already building from this Dockerfile via a Root Directory setting
in the Railway dashboard (invisible to me from the repo). Adding a guessed
config file risked conflicting with a setup that already works. If redeploying
doesn't pick up this Dockerfile change, check your Railway service's Build
settings — confirm Builder is "Dockerfile" and Root Directory is
`backend/cybersentinel-backend`.
