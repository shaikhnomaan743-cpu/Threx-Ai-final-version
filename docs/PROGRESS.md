# THREX performance & correctness upgrade — progress log

Target (agreed): **120,000 flows/sec sustained, end-to-end** (flow records in ->
all 7 detector modules -> alerts persisted + dashboard), >= 60 s, 0 drops,
**p95 latency <= 250 ms**, on Lenovo Legion 5i (i7-14650HX, 8P+8E / 24T),
with detection no worse than baseline (`scripts/evaluate_detectors.py`).
Per-core gate verifiable in the 1-vCPU sandbox: >= 10,000 flows/s end-to-end.

Rules: 52+ tests pass at every checkpoint; protected files untouched
(dga_classifier.py, train_dga.py, measure_throughput.py,
throughput_measurement.json, *.joblib).

## CP0 — Baseline (1 sandbox vCPU)
| Stage | Rate |
|---|---|
| Replay producer (sleep 1 ms per flow) | ~886 flows/s Linux; likely ~64/s on Windows (15 ms timer) |
| JSON flow record -> FlowState | ~22,000/s |
| scapy pcap parse | ~5,300 packets/s (FlowBuilder alone 159k/s) |
| Detection, batch 256 | ~2,800 flows/s |
| Detection + dispatch (process_flows_batch) | ~1,900 flows/s |
| AlertManager.add_alert | ~15,000/s |
| NetFlow/IPFIX/sFlow ingest | not implemented |

Detection baseline: `data/baseline_detector_evaluation.json`
(DGA real held-out 97.06% acc; pipeline: ddos 98.8%, slowloris 0%, dns_tunnel 100%,
dga(lab) 41%, c2 60.5%, port_scan 100%, tls 100%, exfil 100%, benign FPR 2.27%).

Correctness bugs found: alerts never persisted to DB; live sniffer re-enqueues
every active flow every 2 s; replay pacing caps throughput.

## CP1 — Correctness fixes ✅
- **Alert persistence** (correction: alerts WERE persisted, via `get_db()` in
  `AlertManager.add_alert`, but with a new connection + commit per alert on the
  event loop). Now `app/alerts/writer.py`: one WAL connection in a background
  thread, batched `executemany`. 20k alerts/s+ persisted; restart restores all.
- **Dedup** was a linear scan over all active alerts per add (O(n) -> slows under
  spoofed-source floods). Now an O(1) index. Active alerts bounded (`max_active`),
  oldest evicted from memory (still in DB).
- **Live capture** re-enqueued every active flow every 2 s and on EVERY packet
  once 50 flows were open. Now `FlowBuilder.export_ready()`: NetFlow-style export
  once on FIN/RST, 15 s idle, or 30 s active timeout. PCAP path uses `export_all()`.
- **Per-flow series capped** at 64 (timestamps, sizes, `_packets`); counters exact.
- **Replay producer**: per-flow `sleep(0.001)` replaced by chunked, time-based
  pacing. Unthrottled replay now worker-limited (~1,600 flows/s 1 vCPU) instead
  of sleep-limited (~886 Linux / ~64 Windows).
- Writer flushed on shutdown. New tests: `tests/test_ingest_and_persistence.py`
  (5). Suite: 57 passed.

## CP2 — Slowloris / slow-rate DoS ✅
- New `app/models/slowloris_detector.py` (reports as `ddos`, PS category a;
  model_version `slow_rate_dos_v1`). Per flow: long TCP to a web port, tiny
  packets, trickle rate, steady (no silence > 45 s). Cross flow: >= 8 such
  sockets open at once to the same dst:port.
- Lab generator gained `generate_slowloris_tool()` (tool-faithful: 150
  concurrent sockets, header every 10-15 s) and `generate_benign_keepalive()`
  (hard negative). Not called by main(), committed pcaps unchanged.
- Results (3 seeds): tool-faithful Slowloris **0% -> 95.3%**; idle keep-alive
  hard negative **0.00% FP**; benign FPR unchanged (2.27%). The legacy
  generator profile (1 socket / 30 s spread over 5 servers, never concurrent)
  stays ~0-2% by design: it does not model an exhaustion attack.
- Regression gate: `scripts/check_detection_regression.py` (same inputs as
  baseline; fails on >0.5 pp drop). PASS: identical to baseline on all classes.
- Tests: 60 passed (+3 `tests/test_slowloris.py`).

## CP3 — Flow ingest ✅
- `app/ingest/flow_records.py`: NetFlow v5, v9 and IPFIX decoder (+ IPFIX and
  v5 encoders). Output = the lab JSON schema, so IPFIX flows take the exact
  replay path. THREX enterprise IEs (PEN 32473, RFC 5612 example PEN) carry DNS
  name/type, JA3, ClientHello counts, size/timing series, scan fan-out.
  Plain NetFlow v5/v9 has no DNS/TLS fields: DGA, DNS-tunnel, TLS modules
  idle there; the other modules work.
  **Equivalence proven**: 360 flows, 9 traffic types -> identical alerts and
  confidences direct vs via IPFIX. Sequence-gap loss accounting per exporter.
- `app/ingest/flow_collector.py`: listen-only UDP collector (never sends),
  32 MB receive buffer, drops counted. Enable with
  `CYBERSENTINEL_FLOW_LISTEN_PORT=4739`; data_source becomes FLOW_RECORDS.
  Live test: 120,127 records at 20k/s -> 120,127 received, 0 gaps.
- `scripts/flow_exporter.py`: pre-encoded labelled IPFIX at a target rate,
  re-stamped sequence numbers (demo + benchmark driver).
- `app/ingest/fast_pcap.py`: dependency-free pcap/pcapng parser.
  **5,300 -> 122,000 packets/s** (1 vCPU, incl. FlowBuilder). Fixes: DNS over
  UDP now extracted (scapy path only looked at TCP -> DGA/DNS-tunnel never saw
  names from PCAPs); real JA3 (was TLS version / 4 cipher ids); query names were
  "b'...'" strings. scapy kept as fallback.
- Measured ingest cost (1 vCPU): IPFIX decode 37k rec/s, record->FlowState
  16.5k/s => ~11.5k flows/s per process BEFORE detection. Consequence for CP5:
  decoding must happen inside the parallel workers, not in one receiver.
- Tests: 71 passed (+7 codec, +4 pcap). Regression gate: PASS.

## CP3 — Flow ingest ✅ (built in a turn whose tool log dropped out of context; reviewed + verified afterwards)
- `app/ingest/flow_records.py`: NetFlow v5 / v9 / IPFIX decoder -> SAME dict
  schema as lab JSON (so replay and IPFIX flows are processed identically).
  Standard IEs + THREX enterprise IEs (PEN 32473, RFC 5612 example PEN) for DNS
  name/type, JA3, ClientHello counts, size/timing series, scan fan-out.
  NetFlow v5/v9 carry no DNS/TLS metadata: DGA/DNS-tunnel/TLS cannot score them.
  Sequence-number gap accounting (= records lost on the one-way UDP feed).
- `app/ingest/flow_collector.py`: listen-only UDP collector (verified: no send
  calls anywhere in app/). Enabled by CYBERSENTINEL_FLOW_LISTEN_PORT.
- `scripts/flow_exporter.py`: IPFIX exporter at a target rate (demo/benchmark).
- `app/ingest/fast_pcap.py`: struct-based PCAP/PCAPNG reader, 273,769 pkt/s vs
  scapy ~5,300 (52x). ALSO FIXES 3 ORIGINAL BUGS (verified in original code):
  DNS over UDP was never parsed (only inside `haslayer(TCP)`), so PCAP uploads
  could not trigger DGA/DNS-tunnel; "ja3" held TLS version / 4 cipher ids, now
  real JA3 (GREASE removed); query names were stored as "b'x.com.'".
- Tests: tests/test_flow_records.py, tests/test_fast_pcap.py.

## CP4 — Detector speed-ups (in progress) 
Exactness-preserving changes; equivalence PROVEN three ways:
(1) regression gate PASS (identical rates), (2) original vs new beacon detector:
0 mismatching outputs / 7,000 flows (1,680 alerts), (3) original engine (run
inside the repo layout) vs new batch engine: identical alerts for ddos, c2,
dns_tunnel, tls, exfil except 2 flows that ALSO differ between two runs of the
ORIGINAL (generator uses time.time(); 4th-decimal rounding noise).
- scan: incremental ref-counted fan-out (O(1) per flow), idle-source eviction.
- ddos: source-entropy computed only for alerting flows; dst windows GC'd.
- beacon: bisect insert, numpy IATs, python pre-filter, Parseval-bound FFT skip,
  bounded state. TLS: one forest pass (predict from predict_proba).
- engine: batch path awaits detectors in sequence (no 5 Tasks/flow); DGA
  scored in ONE LightGBM call per batch (per-flow fallback).
- FINDING (not changed, reported): the intra-flow C2 branch can never alert —
  it needs cv < 0.05 AND FFT score > 0.3, but score <= ~cv^2 (Parseval).
  C2 detection relies on the cross-flow check only.
Speed (1 vCPU): detection 13,394 flows/s (was 2,800); detection+dispatch 10,124/s
(was 1,900); IPFIX decode 52,121/s; record->FlowState 90,446/s.
Single-process end-to-end ~7,700/s. Next: multi-core design (two-stage:
parallel decoders -> src-IP-sharded detector workers; Windows has no
SO_REUSEPORT balancing), realistic-mix measurement, remaining hot spots.
Tests: 71 passed.

## CP5 — Multi-core pipeline ✅ (functionally verified; scaling must be measured on the laptop)
`app/ingest/parallel.py` (Windows-safe: spawn, no SO_REUSEPORT):
receiver/splitter process -> N detection workers -> dst aggregators -> main.
- Receiver does NOT decode: walks record boundaries, reads src address, routes
  raw record bytes by crc32(src) (not hash(): randomised per process).
  Sequence-gap loss accounting lives here (sees every message). Templates are
  re-stamped per worker. Tests: split is lossless + source-consistent (IPFIX,
  NetFlow v5), exporter-side loss detected.
- MEASURED, then fixed: pure source sharding dropped C2 from 74.5% to 0% (lab
  C2 uses a random source per beacon, so only the destination fan-in check
  sees it) and Slowloris-tool 95.3% -> 92.2%. Destination-level C2 and slow-
  rate concurrency now run in dst aggregators (crc32(dst) % A) fed by every
  worker, with the exact single-process logic. `evaluate_detectors.py --shards 8`
  now matches single-process on EVERY class and on FPR.
- Bug found & fixed: single-flow batches bypassed the batch path in worker
  mode (would have skipped destination checks).
- `scripts/benchmark_pipeline.py`: exporter -> full pipeline -> real
  AlertManager + persistence (temp DB) + push; sustained rate over a window,
  p50/p95/p99 receipt->detection latency, loss (seq gaps, queue drops,
  unprocessed). `--mix lab` (30% attacks) and `--mix realistic` (3%).
  Sandbox functional run (1 vCPU, 2 workers, 2.5k/s): 0 seq gaps, 0 drops,
  0 unprocessed, alerts persisted. (Latency there is meaningless: 6 procs/1 core.)
- App: CYBERSENTINEL_PARALLEL_WORKERS=N with CYBERSENTINEL_FLOW_LISTEN_PORT.

## CP6 — Alert output at scale ✅
- `AlertPump` (pipeline.py), shared by app AND benchmark: every alert
  deduplicated + persisted; only NEW alerts pushed live; push capped at 200/s
  (token bucket), suppressed pushes counted (all alerts still in DB/REST).
- Main-process capacity measured ~15.5k alerts/s per core: at 120k flows/s with
  the lab mix (~29k raw alerts/s) it would bottleneck. Fix: workers coalesce
  identical-key detections per batch with AlertManager's own merge rule and a
  `_coalesced` count; manager counters add it. Test proves identical manager
  state + exact counters vs one-by-one. Tests: 75 passed.

## CP7 — Dashboard metrics ✅
- Workers send per-batch flow/packet/byte totals + receipt->detection latency;
  main process records them in bulk (`record_flows_bulk`,
  `record_latency_samples_ms`). `/api/v1/metrics/throughput` gains a
  `pipeline` block: mode, workers, aggregators, latency basis, loss counters,
  alert push stats. System page shows Pipeline / latency p95 (with basis) /
  flow-record loss / live-push-vs-held.
- Services panel no longer shows Redis/Postgres as "up" (the app stores
  alerts in SQLite); it lists the components that actually run.
- Integration test (real app, multi-core, 2 workers, sandbox): 19,002/19,002
  records processed, 0 loss on every counter, alerts served by /threats/.

## CP8 — Benchmark + docs ✅ (laptop run pending — see TESTING_ON_LAPTOP.md)
- README "Throughput" rewritten around the end-to-end multi-core benchmark;
  the unbacked 1,978.6 / 162.7 figures removed; laptop row left blank until
  measured. MODEL_DOCUMENTATION: stale "synthetic DGA, test AUC 1.0" section
  replaced with the real held-out validation; new table of what each model is
  trained on (DDoS/exfil/TLS = synthetic, 4 train_*.py scripts broken);
  Slowloris section; dead C2 intra-flow branch documented.
- Checks: 75 tests, regression gate PASS, regenerate_evaluation --check OK.

## Still open
- YOUR LAPTOP RUN (TESTING_ON_LAPTOP.md) — the 120k claim is unproven until then.
- Not touched (flagged): System page "Architecture Constraints: All satisfied"
  and "Diode: PASS-THRU" are static labels; 45 dead frontend files (incl.
  mockData.ts); JA4/QUIC not implemented; DDoS/exfil/TLS need real training data.
- CP9 (optional) tool-generated training data; CP10 PPT (reminders saved in chat).
