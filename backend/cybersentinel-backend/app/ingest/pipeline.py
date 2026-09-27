from __future__ import annotations
import asyncio
import time
import os
import logging
from typing import Any, Optional

from app.config import settings

logger = logging.getLogger(__name__)

# Global ingest stats — exposed via /ingest/status
#
# NOTE: current_throughput_fps used to be seeded to the lab benchmark constant
# (88.6) and then "varied slightly" with a hash of the loop counter, so the API
# reported a fabricated rate that had nothing to do with what the process was
# actually doing. It is now read straight from FlowMetrics, which counts real
# flows over a real wall-clock interval.
_stats = {
    "data_source": "LAB_REPLAY",  # LAB_REPLAY | PCAP_REPLAY | LIVE_INGEST | FLOW_RECORDS | BACKEND_SEEDED
    "live_interface": None,
    "packets_received": 0,
    "flows_processed": 0,
    "inference_latency_ms": 0.0,
    "alerts_generated": 0,
    "return_path": "NONE",
    "uptime_seconds": 0.0,
    "current_throughput_fps": 0.0,
}
_start = time.time()
_lock = asyncio.Lock()


def get_ingest_status() -> dict:
    copy = dict(_stats)
    copy["uptime_seconds"] = round(time.time() - _start, 1)
    # Real measured rate + real latency percentiles, not a stored constant.
    try:
        from app.metrics.collector import get_metrics
        m = get_metrics()
        tp = m.get_throughput_stats()
        lat = m.get_latency_stats()
        q = m.get_queue_stats()
        copy["current_throughput_fps"] = tp.get("flows_per_sec", 0.0)
        copy["peak_throughput_fps"] = tp.get("peak_flows_per_sec", 0.0)
        copy["inference_latency_ms"] = lat.get("p50_ms", 0.0)
        copy["inference_latency_p95_ms"] = lat.get("p95_ms", 0.0)
        copy["inference_latency_p99_ms"] = lat.get("p99_ms", 0.0)
        copy["queue_depth"] = q.get("queue_depth", 0)
        copy["dropped_flows"] = q.get("dropped_flows", 0)
    except Exception as e:
        logger.debug("metrics unavailable for ingest status: %s", e)
    # live detection
    iface = os.environ.get("CYBERSENTINEL_LIVE_INTERFACE") or getattr(settings, "live_interface", None)
    if iface:
        copy["data_source"] = "LIVE_INGEST"
        copy["live_interface"] = iface
    elif _stats["data_source"] == "BACKEND_SEEDED":
        pass
    elif _stats["flows_processed"] > 0 and _stats["data_source"] not in ("LIVE_INGEST","PCAP_REPLAY"):
        # if we have processed flows via pipeline, mark appropriately
        pass
    try:
        from app.ingest.flow_collector import get_collector_stats
        cs = get_collector_stats()
        if cs is not None:
            copy["flow_collector"] = cs
    except Exception:
        pass
    copy["return_path"] = "NONE"
    return copy

async def _inc_packets(n:int=1):
    async with _lock:
        _stats["packets_received"] += n

async def _inc_flows():
    async with _lock:
        _stats["flows_processed"] += 1

async def _record_latency(ms:float):
    async with _lock:
        # EMA
        prev = _stats["inference_latency_ms"]
        _stats["inference_latency_ms"] = round(prev*0.9 + ms*0.1 if prev else ms, 2)

async def _inc_alerts(n:int=1):
    async with _lock:
        _stats["alerts_generated"] += n

_warned_no_engine = False

# ── Async ingest queue ────────────────────────────────────────────────
# Capture (replay loop or live sniffer) is the producer; a single worker task
# is the consumer. The producer only ever does queue.put_nowait(), so packet
# ingestion never waits on model inference and cannot stall the event loop.
# When the queue is full we drop and count the drop rather than applying
# backpressure to a passive tap we cannot slow down anyway — and the drop
# count is reported, so "zero drops" is a measurement, not an assumption.
_flow_queue: asyncio.Queue | None = None
_worker_task: asyncio.Task | None = None


def get_queue_depth() -> int:
    return _flow_queue.qsize() if _flow_queue is not None else 0


def enqueue_flow(flow, flow_metrics=None) -> bool:
    """Non-blocking enqueue. Returns False if the flow was dropped."""
    global _flow_queue
    if _flow_queue is None:
        return False
    try:
        _flow_queue.put_nowait(flow)
        if flow_metrics is not None:
            try:
                flow_metrics.set_queue_depth(_flow_queue.qsize())
            except Exception:
                pass
        return True
    except asyncio.QueueFull:
        if flow_metrics is not None:
            try:
                flow_metrics.record_drop(1)
            except Exception:
                pass
        return False


async def enqueue_flow_blocking(flow, flow_metrics=None) -> bool:
    """Enqueue with backpressure — waits rather than dropping.

    Used by file/replay producers, where the source can legitimately be slowed
    down: the reader simply waits for the worker to catch up, so a replay
    reports zero drops because none occurred, not because we stopped counting.
    A live tap cannot be slowed, so live capture uses enqueue_flow() and
    accounts for what it loses.
    """
    global _flow_queue
    if _flow_queue is None:
        return False
    await _flow_queue.put(flow)
    if flow_metrics is not None:
        try:
            flow_metrics.set_queue_depth(_flow_queue.qsize())
        except Exception:
            pass
    return True


async def _batch_worker(alert_manager, inference_engine, broadcaster, flow_metrics):
    """Drain the ingest queue in batches and score them together.

    Batches on size OR timeout, whichever comes first: size keeps throughput
    high (one sklearn call per batch instead of per flow), timeout keeps p95
    latency bounded when traffic is light.
    """
    assert _flow_queue is not None
    batch_size = max(1, int(settings.ingest_batch_size))
    timeout_s = max(0.001, settings.ingest_batch_timeout_ms / 1000.0)
    logger.info(
        "Ingest worker started (batch_size=%d, batch_timeout=%.0fms, queue_max=%d)",
        batch_size, settings.ingest_batch_timeout_ms, settings.ingest_queue_maxsize,
    )
    while True:
        try:
            first = await _flow_queue.get()
            batch = [first]
            deadline = time.monotonic() + timeout_s
            while len(batch) < batch_size:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    batch.append(await asyncio.wait_for(_flow_queue.get(), timeout=remaining))
                except asyncio.TimeoutError:
                    break
            try:
                flow_metrics.set_queue_depth(_flow_queue.qsize())
            except Exception:
                pass
            try:
                await process_flows_batch(batch, alert_manager, inference_engine, broadcaster, flow_metrics)
            finally:
                # Mark every item done even on failure, or queue.join() —
                # used by the PCAP replay path to know when a file has been
                # fully scored — would hang forever on a single bad batch.
                for _ in batch:
                    _flow_queue.task_done()
        except asyncio.CancelledError:
            logger.info("Ingest worker cancelled")
            raise
        except Exception as e:
            logger.error("Ingest worker error: %s", e, exc_info=True)
            await asyncio.sleep(0.5)


async def start_ingest_worker(alert_manager, inference_engine, broadcaster, flow_metrics):
    """Create the queue and start the single consumer task."""
    global _flow_queue, _worker_task
    _flow_queue = asyncio.Queue(maxsize=max(1, int(settings.ingest_queue_maxsize)))
    _worker_task = asyncio.create_task(
        _batch_worker(alert_manager, inference_engine, broadcaster, flow_metrics)
    )
    return _worker_task


async def stop_ingest_worker():
    global _worker_task
    if _worker_task and not _worker_task.done():
        _worker_task.cancel()
        try:
            await _worker_task
        except asyncio.CancelledError:
            pass
    _worker_task = None

async def _dispatch_alerts(flow, alerts, alert_manager, broadcaster):
    """Everything that happens to a flow's alerts once detection is done:
    backfill missing fields from the flow, persist via AlertManager, broadcast
    over both websocket paths, log. Shared by process_flow() (one flow at a
    time) and process_flows_batch() (many flows, batched inference) so there
    is exactly one place that defines what an alert's lifecycle looks like —
    the two callers only differ in how the alerts were produced."""
    for alert in alerts:
        try:
            # ensure flow_id and IPs are set from flow if missing
            if not getattr(alert, "source_ip", None) or alert.source_ip == "0.0.0.0":
                alert.source_ip = getattr(flow, "src_ip", alert.source_ip)
            if not getattr(alert, "destination_ip", None) or alert.destination_ip == "0.0.0.0":
                alert.destination_ip = getattr(flow, "dst_ip", alert.destination_ip)
            if not getattr(alert, "flow_id", None):
                alert.flow_id = getattr(flow, "key", alert.alert_id)
            # Add to manager (persists to DB)
            alert_manager.add_alert(alert)
            await _inc_alerts(1)
            try:
                from app.metrics.collector import get_metrics
                get_metrics().record_alert(1)
            except Exception:
                pass
            # Broadcast via websocket manager + AlertBroadcaster
            try:
                from app.api.routes.websocket import manager as ws_manager
                await ws_manager.broadcast({"type":"alert","data": alert.model_dump(mode="json") if hasattr(alert,"model_dump") else alert.dict()})
            except Exception as e:
                logger.debug(f"WS broadcast failed: {e}")
            try:
                await broadcaster.broadcast(alert)
            except Exception:
                pass
            logger.debug("Pipeline alert: %s %s %s->%s conf=%.2f", alert.threat_class, alert.severity, alert.source_ip, alert.destination_ip, alert.confidence)
        except Exception as e:
            logger.error(f"Pipeline alert handling error: {e}", exc_info=True)


async def process_flow(flow, alert_manager, inference_engine, broadcaster, flow_metrics):
    """Process a single FlowState through the full pipeline: feature → inference → alert → WS → DB."""
    global _warned_no_engine
    if inference_engine is None:
        # Inference engine failed to initialize (see startup logs for the
        # traceback). Skip rather than crash on every flow — one clear
        # message here beats an identical traceback per flow forever.
        if not _warned_no_engine:
            logger.error("process_flow called with no inference_engine — startup init failed, skipping all flows")
            _warned_no_engine = True
        return
    t0 = time.time()
    try:
        # Metrics: record flow
        try:
            flow_metrics.record_flow(flow)
        except Exception:
            pass
        await _inc_flows()
        # Estimate packets from flow
        await _inc_packets(getattr(flow, "packet_count", 1))

        # Inference
        alerts = await inference_engine.analyze_flow(flow)
        latency_ms = (time.time() - t0) * 1000
        await _record_latency(latency_ms)
        try:
            flow_metrics.record_inference_latency(latency_ms/1000)
        except Exception:
            pass

        await _dispatch_alerts(flow, alerts, alert_manager, broadcaster)
        return alerts
    except Exception as e:
        logger.error(f"Pipeline process_flow error: {e}", exc_info=True)
        return []


async def process_flows_batch(flows, alert_manager, inference_engine, broadcaster, flow_metrics):
    """Process many flows through the same pipeline as process_flow(), but
    run detection with InferenceEngine.analyze_flows_batch() so the sklearn
    detectors (ddos, tls, exfil) are scored once for the whole batch instead
    of once per flow. Alert handling (persist, broadcast, log) is identical
    per flow — it goes through the same _dispatch_alerts() as process_flow(),
    so nothing downstream of detection needs to know a batch was involved.

    Returns a flat list of all alerts generated across the batch, in flow order.
    """
    global _warned_no_engine
    if inference_engine is None:
        if not _warned_no_engine:
            logger.error("process_flows_batch called with no inference_engine — startup init failed, skipping all flows")
            _warned_no_engine = True
        return []
    if not flows:
        return []

    t0 = time.time()
    try:
        for flow in flows:
            try:
                flow_metrics.record_flow(flow)
            except Exception:
                pass

        alerts_per_flow = await inference_engine.analyze_flows_batch(flows)

        batch_latency_ms = (time.time() - t0) * 1000
        per_flow_latency_ms = batch_latency_ms / max(len(flows), 1)
        await _record_latency(per_flow_latency_ms)
        try:
            flow_metrics.record_inference_latency(per_flow_latency_ms / 1000)
        except Exception:
            pass

        all_alerts = []
        for flow, alerts in zip(flows, alerts_per_flow):
            await _inc_flows()
            await _inc_packets(getattr(flow, "packet_count", 1))
            await _dispatch_alerts(flow, alerts, alert_manager, broadcaster)
            all_alerts.extend(alerts)
        return all_alerts
    except Exception as e:
        logger.error(f"Pipeline process_flows_batch error: {e}", exc_info=True)
        return []


async def ingest_pcap_file(filepath: str, alert_manager, inference_engine, broadcaster, flow_metrics, data_source: str = "PCAP_REPLAY"):
    """Replay a PCAP/JSON flow file through the pipeline."""
    from app.ingest.pcap_reader import parse_json_flow_file
    flows = parse_json_flow_file(filepath)
    if not flows:
        # try pcap_reader async
        from app.ingest.pcap_reader import pcap_reader
        from app.ingest.flow_builder import FlowBuilder
        builder = FlowBuilder()
        async for pkt in pcap_reader(filepath):
            builder.add_packet(pkt)
        flows = builder.export_all()
    _stats["data_source"] = data_source
    logger.info(f"Ingest {data_source}: {len(flows)} flows from {filepath}")
    # Score the file directly in batches rather than pushing it onto the shared
    # ingest queue.
    #
    # An earlier version enqueued the flows and then awaited queue.join(). That
    # deadlocks: the continuous replay producer keeps adding work, so the queue
    # never reaches zero outstanding items and join() waits forever — the upload
    # request simply hung. Processing here also means the returned
    # flows/alerts counts describe THIS file rather than whatever else the
    # pipeline happened to be doing.
    batch_size = max(1, int(settings.ingest_batch_size))
    for i in range(0, len(flows), batch_size):
        await process_flows_batch(
            flows[i:i + batch_size],
            alert_manager, inference_engine, broadcaster, flow_metrics,
        )
        await asyncio.sleep(0)  # keep the server responsive on large files
    return len(flows)

async def ingest_lab_flow(flow_dict: dict, alert_manager, inference_engine, broadcaster, flow_metrics):
    """Inject a single lab flow dict (for final acceptance test) through the same pipeline."""
    from app.ingest.pcap_reader import _flowstate_from_json
    # If flow_dict already looks like a FlowState dict, convert
    if "src_ip" not in flow_dict and "source_ip" in flow_dict:
        # frontend style, map
        flow_dict = {
            "src_ip": flow_dict.get("source_ip"),
            "dst_ip": flow_dict.get("destination_ip"),
            "src_port": flow_dict.get("source_port"),
            "dst_port": flow_dict.get("destination_port"),
            "protocol": flow_dict.get("protocol","tcp"),
            "packet_count": flow_dict.get("packet_count", 10),
            "bytes_transferred": flow_dict.get("bytes_transferred", 1000),
            "duration_seconds": flow_dict.get("duration_seconds", 1.0),
            "raw_features": flow_dict.get("raw_features", {}),
            "timestamps": flow_dict.get("timestamps", []),
        }
    flow = _flowstate_from_json(flow_dict)
    if not flow:
        raise ValueError("Invalid flow dict")
    # Mark data source as LAB_REPLAY for lab injection unless LIVE_INGEST is active
    if _stats["data_source"] == "LAB_REPLAY":
        _stats["data_source"] = "LAB_REPLAY"
    return await process_flow(flow, alert_manager, inference_engine, broadcaster, flow_metrics)

async def start_background_ingest(alert_manager, inference_engine, broadcaster, flow_metrics):
    """Start background ingest: watches PCAP dir and optionally live interface."""
    # Start the consumer first so nothing is produced into a missing queue.
    await start_ingest_worker(alert_manager, inference_engine, broadcaster, flow_metrics)

    flow_port = int(getattr(settings, "flow_listen_port", 0) or 0)
    if flow_port:
        # Exported flow records (NetFlow v5/v9 / IPFIX) - the PS-named input
        # for high-rate links. Listen-only; flows enqueue non-blocking and
        # overflow is counted as drops (a live feed cannot be slowed down).
        workers = int(getattr(settings, "parallel_workers", 0) or 0)
        if workers > 0:
            # Multi-core: receiver/splitter + N detection worker processes.
            asyncio.create_task(run_parallel_ingest(alert_manager, broadcaster,
                                                    settings.flow_listen_host, flow_port, workers))
            return
        from app.ingest.flow_collector import start_flow_collector
        _stats["data_source"] = "FLOW_RECORDS"
        await start_flow_collector(settings.flow_listen_host, flow_port,
                                   lambda f: enqueue_flow(f, flow_metrics))
        return

    iface = os.environ.get("CYBERSENTINEL_LIVE_INTERFACE") or getattr(settings, "live_interface", None)
    if iface:
        _stats["data_source"] = "LIVE_INGEST"
        _stats["live_interface"] = iface
        logger.info(f"Background ingest: LIVE_INGEST on {iface} (passive)")
        # live sniff loop — enqueue only, never await inference here, or the
        # sniffer stalls and the kernel ring buffer starts dropping packets.
        from app.ingest.live_sniffer import live_sniffer
        from app.ingest.flow_builder import FlowBuilder
        builder = FlowBuilder()
        last_flush = time.time()
        async for pkt in live_sniffer(iface=iface):
            builder.add_packet(pkt)
            await _inc_packets(1)
            # Export each flow ONCE when it finishes (FIN/RST, idle or active
            # timeout), NetFlow-style. The old loop re-enqueued every active
            # flow on every tick (and on every packet once 50 flows were open),
            # so the same flow was scored and counted repeatedly.
            now = time.time()
            if now - last_flush >= 1.0:
                for flow in builder.export_ready(now):
                    enqueue_flow(flow, flow_metrics)
                last_flush = now
    else:
        # Continuous LAB REPLAY mode for production streaming simulation
        _stats["data_source"] = "LAB_REPLAY"
        logger.info("Background ingest: LAB_REPLAY continuous streaming mode (passive)")
        
        # Load lab data for continuous replay
        lab_candidates = [
            os.path.join(os.path.dirname(__file__), "..", "..", "data", "pcaps", "mixed", "lab_mixed.json"),
            os.path.join(settings.pcap_dir, "mixed", "lab_mixed.json"),
            os.path.join("data", "pcaps", "mixed", "lab_mixed.json"),
        ]
        
        lab_flows = []
        for cand in lab_candidates:
            if os.path.exists(cand):
                try:
                    from app.ingest.pcap_reader import parse_json_flow_file
                    lab_flows = parse_json_flow_file(cand)
                    if lab_flows:
                        logger.info(f"Loaded {len(lab_flows)} lab flows for continuous replay from {cand}")
                        break
                except Exception as e:
                    logger.debug(f"Lab data load failed {cand}: {e}")
        
        if not lab_flows:
            logger.warning("No lab flows found for continuous replay, using seeded data only")
            _stats["data_source"] = "BACKEND_SEEDED"
            return
        
        # Continuous replay loop — the PRODUCER only.
        #
        # It enqueues and yields; it never awaits inference. Throughput is
        # therefore set by the worker draining the queue, not by a sleep
        # constant here, and whatever rate results is measured rather than
        # asserted. replay_target_fps=0 means "go as fast as the pipeline
        # allows", which is what the benchmark script uses.
        flow_index = 0
        target_fps = float(getattr(settings, "replay_target_fps", 0.0) or 0.0)
        pace = (1.0 / target_fps) if target_fps > 0 else 0.0
        logger.info(
            "LAB_REPLAY producer starting (%d flows, pacing=%s)",
            len(lab_flows), f"{target_fps} fps" if pace else "unthrottled",
        )

        # Pacing is time-based and per CHUNK, not a sleep per flow. The old
        # loop slept 1 ms after every flow, which capped replay at <1,000
        # flows/s on Linux and roughly 64 flows/s on Windows (asyncio timer
        # granularity ~15.6 ms) - so the dashboard showed the sleep, not the
        # pipeline. Now: enqueue a chunk, and only sleep when ahead of the
        # target rate, or briefly every ~20 ms so HTTP handlers still run.
        CHUNK = 256
        t0 = time.monotonic()
        last_yield = t0
        produced = 0
        while True:
            try:
                base_time = time.time()
                for _ in range(CHUNK):
                    flow = lab_flows[flow_index % len(lab_flows)]
                    flow_index += 1
                    # Refresh timestamps so periodicity features see a live window.
                    if hasattr(flow, "timestamps") and flow.timestamps:
                        n = len(flow.timestamps)
                        flow.timestamps = [base_time - (n - i) * 0.1 for i in range(n)]
                    # Replay is a source we control, so wait for the worker
                    # rather than dropping. Rate is then set by real capacity.
                    await enqueue_flow_blocking(flow, flow_metrics)
                produced += CHUNK

                now = time.monotonic()
                if pace:
                    ahead = produced * pace - (now - t0)
                    if ahead > 0:
                        await asyncio.sleep(ahead)
                        last_yield = time.monotonic()
                        continue
                if now - last_yield >= 0.02:
                    await asyncio.sleep(0.001)
                    last_yield = time.monotonic()

            except asyncio.CancelledError:
                logger.info("Continuous LAB REPLAY stopped")
                break
            except Exception as e:
                logger.error(f"Error in continuous replay loop: {e}")
                await asyncio.sleep(1)


class AlertPump:
    """Main-process side of the multi-core pipeline (and the benchmark).

    Every alert is deduplicated and persisted through AlertManager, exactly
    as in the single-process path. What changes is the LIVE PUSH: only a NEW
    alert (not a merge into an existing one) is broadcast, and broadcasts are
    capped by a token bucket (default 200/s). At 100k+ flows/s an attack can
    produce tens of thousands of raw detections per second; pushing each one
    over websockets would stall this process and freeze the browser. Nothing
    is lost: suppressed pushes are counted, and every alert is in the
    database / REST API that the dashboard polls.
    """

    def __init__(self, alert_manager, broadcaster, max_push_per_sec: float = 200.0):
        self.am, self.bc = alert_manager, broadcaster
        self.rate = max_push_per_sec
        self.tokens, self.t_last = max_push_per_sec, time.monotonic()
        self.stats = {"alerts_in": 0, "alerts_new": 0, "alerts_merged": 0,
                      "pushed": 0, "push_suppressed": 0, "flows": 0}
        self._ws = None

    def _take_token(self) -> bool:
        now = time.monotonic()
        self.tokens = min(self.rate, self.tokens + (now - self.t_last) * self.rate)
        self.t_last = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False

    async def handle(self, msg) -> None:
        kind = msg[0]
        if kind == "stats":                      # worker receipt->detection latency samples
            try:
                from app.metrics.collector import get_metrics
                get_metrics().record_latency_samples_ms(msg[3])
            except Exception:
                pass
            return
        if kind != "batch":
            return
        n_flows, alerts = msg[2], msg[3]
        self.stats["flows"] += n_flows
        if n_flows:
            _stats["flows_processed"] += n_flows
            try:
                from app.metrics.collector import get_metrics
                get_metrics().record_flows_bulk(n_flows, msg[4] if len(msg) > 4 else 0,
                                                msg[5] if len(msg) > 5 else 0)
            except Exception:
                pass
        for alert in alerts:
            rf = getattr(alert, "raw_features", None) or {}
            n_det = int(rf.get("_coalesced", 1) or 1)       # detections folded in by the worker
            self.stats["alerts_in"] += n_det
            stored = self.am.add_alert(alert) if self.am is not None else alert
            if stored is None:
                continue
            if stored.alert_id != alert.alert_id:
                self.stats["alerts_merged"] += n_det
                continue
            self.stats["alerts_new"] += 1
            self.stats["alerts_merged"] += n_det - 1
            _stats["alerts_generated"] += 1
            if not self._take_token():
                self.stats["push_suppressed"] += 1
                continue
            self.stats["pushed"] += 1
            try:
                if self._ws is None:
                    from app.api.routes.websocket import manager as ws_manager
                    self._ws = ws_manager
                await self._ws.broadcast({"type": "alert", "data": stored.model_dump(mode="json")})
            except Exception as e:
                logger.debug("WS broadcast failed: %s", e)
            try:
                if self.bc is not None:
                    await self.bc.broadcast(stored)
            except Exception:
                pass


async def run_parallel_ingest(alert_manager, broadcaster, host: str, port: int, n_workers: int):
    """Start the multi-core pipeline and pump its results into this process."""
    from app.ingest.parallel import ParallelPipeline
    loop = asyncio.get_running_loop()
    pipe = await loop.run_in_executor(None, lambda: ParallelPipeline(host, port, n_workers).start())
    pump = AlertPump(alert_manager, broadcaster)
    _stats["data_source"] = "FLOW_RECORDS"
    _stats["parallel"] = {"workers": n_workers, "dst_aggregators": len(pipe.agg_qs)}
    _parallel_state["pipe"], _parallel_state["pump"] = pipe, pump
    logger.info("Multi-core flow pipeline: %d workers, %d dst aggregators, udp://%s:%d",
                n_workers, len(pipe.agg_qs), host, port)
    import queue as _q
    try:
        while True:
            got = False
            for _ in range(256):
                try:
                    msg = pipe.out_q.get_nowait()
                except _q.Empty:
                    break
                got = True
                await pump.handle(msg)
            try:
                while True:
                    _, s = pipe.stats_q.get_nowait()
                    _parallel_state["receiver"] = s
            except _q.Empty:
                pass
            await asyncio.sleep(0 if got else 0.01)
    finally:
        pipe.stop()


_parallel_state: dict = {}
