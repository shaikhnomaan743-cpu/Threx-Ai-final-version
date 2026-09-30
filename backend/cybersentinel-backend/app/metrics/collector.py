from __future__ import annotations

import time
import threading
import logging
from collections import defaultdict
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

try:
    from prometheus_client import Counter, Histogram, REGISTRY, generate_latest  # type: ignore
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    REGISTRY = None  # type: ignore


def _safe_counter(name: str, doc: str):
    """Create Counter safely, reusing existing if already registered."""
    if not PROMETHEUS_AVAILABLE:
        return None
    try:
        return Counter(name, doc)
    except ValueError as e:
        # Already registered – reuse from registry
        if "Duplicated" in str(e) or "already" in str(e).lower():
            try:
                for collector in REGISTRY._names_to_collectors.values():  # type: ignore
                    if hasattr(collector, "_name") and collector._name == name:
                        return collector
                # Fallback: try to get existing metric by name via registry
                return REGISTRY._names_to_collectors.get(name)  # type: ignore
            except Exception:
                pass
        # Return dummy no-op
        class _Noop:
            def inc(self, v=1): pass
            def observe(self, v): pass
        return _Noop()
    except Exception:
        class _Noop:
            def inc(self, v=1): pass
            def observe(self, v): pass
        return _Noop()


def _safe_histogram(name: str, doc: str, buckets=None):
    if not PROMETHEUS_AVAILABLE:
        return None
    try:
        if buckets:
            return Histogram(name, doc, buckets=buckets)
        return Histogram(name, doc)
    except ValueError:
        # reuse existing
        try:
            return REGISTRY._names_to_collectors.get(name)  # type: ignore
        except Exception:
            pass
        class _Noop:
            def observe(self, v): pass
        return _Noop()
    except Exception:
        class _Noop:
            def observe(self, v): pass
        return _Noop()


class FlowMetrics:
    """Counts and tracks flow/packet/byte metrics for the pipeline."""

    def __init__(self):
        # Flow counters (reset per monitoring interval)
        self._flows_per_sec: float = 0.0
        self._packets_per_sec: float = 0.0
        self._bytes_per_sec: float = 0.0
        self._last_flows_sec: float = 0.0
        self._last_packets_sec: float = 0.0
        self._last_bytes_sec: float = 0.0

        # Per-protocol counters
        self._protocol_counts: Dict[str, int] = defaultdict(int)

        # Time tracking
        self._last_reset = time.time()
        self._interval = 1.0  # 1-second reporting interval

        # History: per-second aggregates, {epoch_second: {flows,packets,bytes}}
        self._history_size = 60
        self._flow_history: list = []  # retained for backwards compatibility
        self._second_buckets: dict = {}
        self._retention_seconds = 600

        # Thread safety
        self._lock = threading.Lock()

        # Prometheus metrics (if available) – safe creation
        if PROMETHEUS_AVAILABLE:
            self._flows_counter = _safe_counter("cybersentinel_flows_total", "Total number of flows processed")
            self._packets_counter = _safe_counter("cybersentinel_packets_total", "Total number of packets processed")
            self._bytes_counter = _safe_counter("cybersentinel_bytes_total", "Total number of bytes processed")
            self._inference_latency = _safe_histogram(
                "cybersentinel_inference_latency_seconds",
                "Latency of inference engine per flow",
                buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0],
            )
            self._flow_rate = _safe_histogram(
                "cybersentinel_flow_rate_per_sec",
                "Flows processed per second",
                buckets=[100, 500, 1000, 5000, 10000, 20000, 50000],
            )
        else:
            self._flows_counter = self._packets_counter = self._bytes_counter = None
            self._inference_latency = self._flow_rate = None

        # Totals for non-reset tracking (used by /metrics fallback)
        self._total_flows = 0
        self._total_packets = 0
        self._total_bytes = 0

        # Real latency distribution (milliseconds), bounded ring buffer.
        self._latency_window: list = []
        self._latency_window_size = 1000
        self._total_inferences = 0

        # Queue / loss telemetry, fed by the ingest worker.
        self._queue_depth = 0
        self._dropped_flows = 0
        self._total_alerts = 0

        # Sustained-rate tracking: peak observed 1s rate since boot.
        self._peak_flows_sec = 0.0
        self._boot_time = time.time()

    def record_flow(self, flow: Any):
        """Record a new flow for metrics tracking.

        Thread-safe, tracks prometheus counters and internal rates.
        """
        now = time.time()
        with self._lock:
            self._flows_per_sec += 1
            pkt_cnt = getattr(flow, "packet_count", 0) or 0
            byte_cnt = getattr(flow, "bytes_transferred", 0) or 0
            self._packets_per_sec += pkt_cnt
            self._bytes_per_sec += byte_cnt

            self._total_flows += 1
            self._total_packets += pkt_cnt
            self._total_bytes += byte_cnt

            protocol = getattr(flow, 'protocol', 'unknown')
            if not isinstance(protocol, str):
                protocol = str(protocol)
            protocol = protocol.lower()
            self._protocol_counts[protocol] = self._protocol_counts.get(protocol, 0) + 1

            # Aggregate into per-second buckets at record time.
            #
            # This used to append one dict per flow and trim to the last 120
            # entries. At a few hundred flows/sec that window covers well under
            # a second, so a 60-second chart had 59 empty buckets and one
            # spike — not because the network was idle, but because the history
            # had already been discarded. Bucketing on write keeps a full
            # retention window at fixed memory cost.
            sec = int(now)
            b = self._second_buckets.get(sec)
            if b is None:
                b = {"flows": 0, "packets": 0, "bytes": 0}
                self._second_buckets[sec] = b
            b["flows"] += 1
            b["packets"] += pkt_cnt
            b["bytes"] += byte_cnt
            if len(self._second_buckets) > self._retention_seconds * 2:
                cutoff = sec - self._retention_seconds
                for k in [k for k in self._second_buckets if k < cutoff]:
                    del self._second_buckets[k]

            if PROMETHEUS_AVAILABLE and self._flows_counter:
                try:
                    self._flows_counter.inc()
                    if self._packets_counter:
                        self._packets_counter.inc(pkt_cnt)
                    if self._bytes_counter:
                        self._bytes_counter.inc(byte_cnt)
                except Exception as e:
                    logger.debug(f"Prometheus inc error: {e}")

    def record_flows_bulk(self, n: int, packets: int, byte_count: int):
        """Multi-core path: one call per worker batch instead of per flow
        (per-flow bookkeeping in the main process would re-create the very
        bottleneck the workers remove). Same counters and 1 s buckets."""
        if n <= 0:
            return
        now = time.time()
        with self._lock:
            self._flows_per_sec += n
            self._packets_per_sec += packets
            self._bytes_per_sec += byte_count
            self._total_flows += n
            self._total_packets += packets
            self._total_bytes += byte_count
            sec = int(now)
            b = self._second_buckets.get(sec)
            if b is None:
                b = {"flows": 0, "packets": 0, "bytes": 0}
                self._second_buckets[sec] = b
            b["flows"] += n
            b["packets"] += packets
            b["bytes"] += byte_count
            if len(self._second_buckets) > self._retention_seconds * 2:
                cutoff = sec - self._retention_seconds
                for k in [k for k in self._second_buckets if k < cutoff]:
                    del self._second_buckets[k]
        if PROMETHEUS_AVAILABLE and self._flows_counter:
            try:
                self._flows_counter.inc(n)
                if self._packets_counter:
                    self._packets_counter.inc(packets)
                if self._bytes_counter:
                    self._bytes_counter.inc(byte_count)
            except Exception:
                pass

    def record_latency_samples_ms(self, samples_ms):
        """Bulk latency samples (ms) into the same p50/p95/p99 window."""
        if not samples_ms:
            return
        with self._lock:
            self._latency_window.extend(float(x) for x in samples_ms)
            if len(self._latency_window) > self._latency_window_size * 2:
                self._latency_window = self._latency_window[-self._latency_window_size:]
            self._total_inferences += len(samples_ms)

    def record_inference_latency(self, latency_seconds: float):
        """Record inference engine latency.

        Latencies are also kept in a bounded in-process window so p50/p95/p99
        can be served from /metrics/throughput. Previously this only fed a
        Prometheus histogram and get_latency_stats() returned the string
        "Use prometheus endpoint for latency metrics" — the dashboard had no
        real latency source at all and showed a hardcoded number instead.
        """
        with self._lock:
            self._latency_window.append(float(latency_seconds) * 1000.0)
            if len(self._latency_window) > self._latency_window_size * 2:
                self._latency_window = self._latency_window[-self._latency_window_size:]
            self._total_inferences += 1
        if PROMETHEUS_AVAILABLE and self._inference_latency:
            try:
                self._inference_latency.observe(latency_seconds)
            except Exception:
                pass

    def record_drop(self, n: int = 1):
        """Record flows dropped because the ingest queue was full."""
        with self._lock:
            self._dropped_flows += n

    def set_queue_depth(self, depth: int):
        with self._lock:
            self._queue_depth = int(depth)

    def record_alert(self, n: int = 1):
        with self._lock:
            self._total_alerts += n

    @staticmethod
    def _percentile(sorted_vals: list, q: float) -> float:
        """Nearest-rank percentile. Returns 0.0 on an empty window."""
        if not sorted_vals:
            return 0.0
        k = max(0, min(len(sorted_vals) - 1, int(round(q * (len(sorted_vals) - 1)))))
        return round(sorted_vals[k], 3)

    def get_throughput_stats(self) -> Dict[str, Any]:
        """Get current throughput statistics."""
        with self._lock:
            now = time.time()
            elapsed = now - self._last_reset

            # Calculate rates; if interval not elapsed, return last computed or current scaled
            if elapsed >= self._interval:
                flows_sec = self._flows_per_sec / max(elapsed, 1e-6)
                packets_sec = self._packets_per_sec / max(elapsed, 1e-6)
                bytes_sec = self._bytes_per_sec / max(elapsed, 1e-6)
                self._last_flows_sec = round(flows_sec, 2)
                self._last_packets_sec = round(packets_sec, 2)
                self._last_bytes_sec = round(bytes_sec, 2)
                if self._last_flows_sec > self._peak_flows_sec:
                    self._peak_flows_sec = self._last_flows_sec
                # Reset counters for next interval
                self._flows_per_sec = 0.0
                self._packets_per_sec = 0.0
                self._bytes_per_sec = 0.0
                self._last_reset = now
            else:
                # Return last computed or instantaneous estimate
                if self._last_flows_sec == 0 and elapsed > 0:
                    # instantaneous
                    flows_sec = self._flows_per_sec / max(elapsed, 1e-6)
                    packets_sec = self._packets_per_sec / max(elapsed, 1e-6)
                    bytes_sec = self._bytes_per_sec / max(elapsed, 1e-6)
                else:
                    flows_sec = self._last_flows_sec
                    packets_sec = self._last_packets_sec
                    bytes_sec = self._last_bytes_sec
                # Ensure we return numbers even if no flows yet
                if not isinstance(flows_sec, float):
                    flows_sec = float(flows_sec)

            total_proto = sum(self._protocol_counts.values()) or 1
            protocol_percentages = {
                k: round(v / total_proto * 100, 1)
                for k, v in self._protocol_counts.items()
            }

            return {
                "flows_per_sec": round(float(flows_sec), 2) if isinstance(flows_sec, (int, float)) else 0.0,
                "packets_per_sec": round(float(packets_sec), 2) if isinstance(packets_sec, (int, float)) else 0.0,
                "bytes_per_sec": round(float(bytes_sec), 2) if isinstance(bytes_sec, (int, float)) else 0.0,
                "protocol_distribution": protocol_percentages,
                "active_flows": sum(self._protocol_counts.values()),
                "total_flows": self._total_flows,
                "total_packets": self._total_packets,
                "total_bytes": self._total_bytes,
                "peak_flows_per_sec": round(self._peak_flows_sec, 2),
                "uptime_seconds": round(now - self._boot_time, 2),
                "timestamp": __import__("datetime").datetime.now(
                    __import__("datetime").timezone.utc
                ).isoformat().replace("+00:00", "Z"),
            }

    def get_latency_stats(self) -> Dict[str, Any]:
        """Real inference-latency distribution over the recent window, in ms."""
        with self._lock:
            vals = sorted(self._latency_window[-self._latency_window_size:])
            total = self._total_inferences
        if not vals:
            return {
                "samples": 0, "total_inferences": total,
                "p50_ms": 0.0, "p95_ms": 0.0, "p99_ms": 0.0,
                "min_ms": 0.0, "max_ms": 0.0, "mean_ms": 0.0,
            }
        return {
            "samples": len(vals),
            "total_inferences": total,
            "p50_ms": self._percentile(vals, 0.50),
            "p95_ms": self._percentile(vals, 0.95),
            "p99_ms": self._percentile(vals, 0.99),
            "min_ms": round(vals[0], 3),
            "max_ms": round(vals[-1], 3),
            "mean_ms": round(sum(vals) / len(vals), 3),
        }

    def get_resource_stats(self) -> Dict[str, Any]:
        """Real process CPU/memory. Reports availability rather than inventing
        numbers when psutil is absent, so the UI can show 'unavailable'
        instead of a plausible-looking fake."""
        try:
            import psutil  # type: ignore
        except ImportError:
            return {"available": False, "reason": "psutil not installed"}
        try:
            proc = psutil.Process()
            with proc.oneshot():
                mem = proc.memory_info()
                cpu = proc.cpu_percent(interval=None)
            vm = psutil.virtual_memory()
            return {
                "available": True,
                "cpu_percent": round(float(cpu), 2),
                "memory_rss_mb": round(mem.rss / (1024 * 1024), 2),
                "memory_percent": round(float(proc.memory_percent()), 2),
                "system_memory_percent": round(float(vm.percent), 2),
                "num_threads": proc.num_threads(),
            }
        except Exception as e:  # pragma: no cover - platform dependent
            return {"available": False, "reason": str(e)}

    def get_queue_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "queue_depth": self._queue_depth,
                "dropped_flows": self._dropped_flows,
                "total_alerts": self._total_alerts,
            }

    def get_flow_history(self, buckets: int = 60, bucket_seconds: int = 1) -> list:
        """Aggregate observed traffic into fixed time buckets, oldest first.

        Reads the per-second aggregates recorded by record_flow(). Buckets with
        no traffic are returned as zeros, so a genuinely quiet period looks
        quiet instead of being interpolated over.
        """
        now = int(time.time())
        with self._lock:
            src = dict(self._second_buckets)
        out = []
        for i in range(buckets):
            # bucket i covers [start, start+bucket_seconds)
            end_off = (buckets - i) * bucket_seconds
            start_sec = now - end_off
            agg = {"offset_s": -end_off, "flows": 0, "packets": 0, "bytes": 0}
            for s_i in range(start_sec, start_sec + bucket_seconds):
                b = src.get(s_i)
                if b:
                    agg["flows"] += b["flows"]
                    agg["packets"] += b["packets"]
                    agg["bytes"] += b["bytes"]
            out.append(agg)
        return out

    def prometheus_text(self) -> bytes:
        """Generate prometheus text format including flow counts fallback."""
        if PROMETHEUS_AVAILABLE:
            try:
                from prometheus_client import generate_latest  # type: ignore
                data = generate_latest()
                # generate_latest already includes our counters; return it
                if data and len(data) > 10:
                    return data
            except Exception as e:
                logger.debug(f"generate_latest failed: {e}")
        # Fallback manual exposition
        lines = []
        lines.append("# HELP cybersentinel_flows_total Total number of flows processed")
        lines.append("# TYPE cybersentinel_flows_total counter")
        lines.append(f"cybersentinel_flows_total {self._total_flows}")
        lines.append("# HELP cybersentinel_packets_total Total packets")
        lines.append("# TYPE cybersentinel_packets_total counter")
        lines.append(f"cybersentinel_packets_total {self._total_packets}")
        lines.append("# HELP cybersentinel_bytes_total Total bytes")
        lines.append("# TYPE cybersentinel_bytes_total counter")
        lines.append(f"cybersentinel_bytes_total {self._total_bytes}")
        lines.append("# HELP cybersentinel_active_flows Active flows tracked")
        lines.append("# TYPE cybersentinel_active_flows gauge")
        lines.append(f"cybersentinel_active_flows {sum(self._protocol_counts.values())}")
        return "\n".join(lines).encode("utf-8") + b"\n"


# Global metrics instance
_metrics_instance: FlowMetrics | None = None


def get_metrics() -> FlowMetrics:
    """Get the global metrics instance."""
    global _metrics_instance
    if _metrics_instance is None:
        _metrics_instance = FlowMetrics()
    return _metrics_instance
