# THREX AI — production hardening pass

Scope: eliminate mock data, silent failures and unverifiable claims across the
stack. Every number the app displays is now measured at runtime or read from a
regenerated artifact.

Verification after all changes: **52/52 backend tests pass**, **23/23 endpoints
return 200**, **frontend `tsc -b && vite build` clean**.

---

## Critical

### 1. `pandas` missing from requirements — all six detectors silently dead
`app/models/dga_classifier.py` imports pandas at module scope. It was not in
`requirements.txt`. Following the README exactly, the server still started,
`/health` returned 200 and every endpoint served data — but the log showed
`Inference engine warmup failed` and `process_flow called with no
inference_engine`. **Every response came from 1,000 pre-seeded SQLite rows;
nothing was being detected.**

Fixed: added `pandas>=2.0.0,<4.0.0` with a comment explaining the failure mode.
Pinned all dependencies with upper bounds. Removed unused `aiokafka`. Added
`psutil` (real resource telemetry) and `python-multipart` (upload support).

### 2. Health check structurally could not report a dead engine
`_health_payload()` derived `"inference": "ready"` from the **alert manager**,
not the engine. This is the direct cause of (1) going unnoticed.

Fixed: health now reports real engine state, plus `detection_active` and
`degraded_reason`. Startup **aborts** on engine failure unless
`CYBERSENTINEL_ALLOW_DEGRADED_START=true`. Both paths verified.

### 3. `scripts/regenerate_evaluation.py` did not exist
Slide 5 of the deck states *"Every figure on this deck regenerates from
scripts/regenerate_evaluation.py."* The file was absent — a verifiable false
claim about reproducibility.

Worse, `data/models/evaluation.json` still carried the **pre-audit DGA numbers**
(`train_auc 0.9991`, `test_auc 1.0`) that `AUDIT_2026-09-14.md` had already
shown to be a domain-length artifact, and `lib/utils.ts` hardcoded the same
values into the AI Engine page. **The running app contradicted the deck.** The
correct retrained metrics were sitting unused in
`backend/data/dga_evaluation.json`.

Fixed: wrote the script. It consolidates measured artifacts, refuses to invent
values (missing sources produce `{"available": false, "reason": ...}`), and has
a `--check` mode for CI. Output:

```
DGA cv_auc=0.9966  length_only_baseline=0.9384  tpr=0.961  fpr=0.024
```

### 4. Path traversal in `POST /ingest/pcap`
The endpoint opened a caller-supplied `filepath` directly — any file the
process could read was retrievable. Fixed: paths are resolved and required to
stay within the configured PCAP directory. Verified blocked.

---

## Fabricated data removed

| Location | Was | Now |
|---|---|---|
| `pipeline.py` | `current_throughput_fps = 88.6 + (hash(idx) % 10 - 5)/10` | real `FlowMetrics` counters |
| `system.py` | `flows_per_second = len(alerts) * 0.5` | measured rate |
| `collector.py` | `get_latency_stats()` returned the string "Use prometheus endpoint" | real p50/p95/p99 over a 1,000-sample window |
| `lib/api.ts` | every fetcher ended `catch { return <randomised object> }` | throws `ApiError`; pages show error state |
| `useLiveData.ts` | 1s `setInterval` mutating metrics with `Math.random()`, synthetic alerts at 18% probability when backend down | polls real telemetry only |
| `lib/api.ts` | `TOP_TALKERS` / `DETECTION_MIX` hardcoded literals | computed from live alerts |
| `lib/utils.ts` | `BENCHMARK` (88.6 fps, p50 12.93 ms) and `MODELS` (DGA AUC 1.0) | deleted; served from API |

The frontend fallback was the most dangerous: a backend outage produced a
dashboard full of plausible traffic. For a SOC tool that is the worst possible
failure mode.

---

## Bugs found and fixed

- **Time-series was structurally broken.** Flow history was a fixed 120-entry
  list; at any real rate a 60-second chart showed 59 empty buckets and one
  spike — not because traffic was quiet but because history was discarded.
  Now aggregates per-second on write. Verified: 10 continuous buckets.
- **`ThreatDetail` showed the wrong threat.** On a cache miss it fell back to
  `all[0]`, rendering a *different* alert under the requested URL with no
  indication. Now fetches by ID and distinguishes not-found from fetch failure.
- **Upload deadlock (introduced during this pass, then fixed).** Routing
  uploads through the shared queue and awaiting `queue.join()` hung forever,
  because the continuous replay producer keeps the queue non-empty. Uploads are
  now scored directly in batches.
- **Event-loop starvation.** An unthrottled producer plus the batch worker
  monopolised the loop and the API stopped responding. Replay is throttled by
  default; per-alert logging moved from INFO to DEBUG (it was thousands of
  synchronous stdout writes per second).

---

## Performance

Flow ingestion no longer blocks the event loop: capture enqueues via
`put_nowait`, a worker drains in batches. Replay uses backpressure (it is a
source we control, so it waits rather than dropping); live capture drops and
*counts* drops, because a tap cannot be slowed.

Batched inference, 180 lab flows x5, single shared vCPU:

| batch | flows/sec | p50 | p95 | p99 |
|---|---|---|---|---|
| 1 | 351.5 | 0.613 ms | 11.839 ms | 22.247 ms |
| 64 | 1,303.2 | 0.801 ms | 1.021 ms | 1.021 ms |
| 256 | **1,978.6** | 0.517 ms | 0.538 ms | 0.538 ms |

Serving mode (API responsive, replay throttled): **162.7 flows/sec, p50 1.536 ms,
p95 2.274 ms, p99 3.752 ms, 0 drops, API 0.9–1.5 ms.**

**Quote the serving number, not 1,978.** The ceiling is real but is not a rate
at which the system also serves the dashboard.

---

## Unimplemented features — surfaced, not faked

Per the brief, these render as explicit inactive states:

- **JA3S** — needs the ServerHello, invisible on a one-way tap.
  `/api/v1/analytics/tls` returns `ja3s_available: false` with the reason.
- **Alert triage** — no status field, no PATCH endpoint. Buttons disabled with a
  Phase 2 tooltip rather than wired to a no-op that looks like it worked.
- **Profile** — no route exists; disabled with a reason.
- **CPU/memory** — returns `available: false` if psutil is absent.

---

## Files

**Deleted (31).** Frontend dead tree — 9 unrouted pages (`SystemStatus`,
`TrafficAnalytics`, `TLSAnalytics`, `DNSAnalytics`, `AIDetectionEngine`,
`Exfiltration`, `Reconnaissance`, `AlertCenter`, `ThreatInvestigation`), 11
components (`MainLayout`, `Sidebar`, `TopBar`, `ThroughputSparkline`,
`GlobalSearch`, `DataModeIndicator`, `InfrastructureFooter`, `AlertDrawer`,
`SplashScreen`, `AddNoteDialog`, `DataTable`), and the whole mock stack
(`liveSimulation`, `mockData`, `apiClient`, `services/api`, `searchIndex`,
`useData`, `useLiveMetrics`, `useWebSocket`). Backend: `backend/backend/`
(stale Pydantic v1 tree). Root: 4 one-off scripts, duplicate 7 MB
`dga_domains.csv`, 9.7 MB Tranco zip, `.DS_Store`, caches.

> Note: an earlier review of mine flagged fake data in several of those 9 pages
> as demo risks. That was wrong — they were never routed and never rendered.
> The real fakes were server-side.

**Created (3).** `app/api/routes/metrics_v1.py`, `scripts/regenerate_evaluation.py`,
this file.

**Modified (15).** Backend: `requirements.txt`, `deps.py`, `main.py`, `config.py`,
`collector.py`, `pipeline.py`, `system.py`, `ingest.py`, `manager.py`.
Frontend: `lib/api.ts`, `useLiveData.ts`, `Overview.tsx`, `System.tsx`,
`AIEngine.tsx`, `ThreatDetail.tsx`, `Layout.tsx`, `lib/utils.ts`.
Docs/config: `README.md`, `.gitignore`, three `.env.example` files.

Repo size 56 MB → 40 MB.

---

## Before submitting

1. **Team ID is still blank** on slide 1.
2. Re-run the benchmark on your own hardware and update the deck — the numbers
   above are from a single shared vCPU container.
3. Deck slides 4 and 5 still say `102.7 flows/sec`, `p50 10.0 ms`,
   `p95 32.5 ms`. Reconcile against your own run.
4. Consider a one-line Phase 2 note on the deck for JA4 / QUIC /
   NetFlow-IPFIX — your audit lists them as open, and a judge who read the PS
   will ask.

## Two decorative `Math.random()` calls remain

`PipelineViz.tsx` and `FlowVisualization.tsx` use randomness for particle
scatter and packet-dot animation. That is visual jitter, not data, and no
displayed value derives from it. Removing it would make the animation a static
grid. Flagged here so the "zero RNG" claim is precise rather than technically
overstated.
