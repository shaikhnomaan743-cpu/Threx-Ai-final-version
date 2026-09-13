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

        # History
        self._history_size = 60
        self._flow_history: list = []

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

            self._flow_history.append({
                "timestamp": now,
                "packet_count": pkt_cnt,
                "bytes_transferred": byte_cnt,
            })
            if len(self._flow_history) > self._history_size * 2:
                self._flow_history = self._flow_history[-self._history_size:]

            if PROMETHEUS_AVAILABLE and self._flows_counter:
                try:
                    self._flows_counter.inc()
                    if self._packets_counter:
                        self._packets_counter.inc(pkt_cnt)
                    if self._bytes_counter:
                        self._bytes_counter.inc(byte_cnt)
                except Exception as e:
                    logger.debug(f"Prometheus inc error: {e}")

    def record_inference_latency(self, latency_seconds: float):
        """Record inference engine latency."""
        if PROMETHEUS_AVAILABLE and self._inference_latency:
            try:
                self._inference_latency.observe(latency_seconds)
            except Exception:
                pass

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
                "timestamp": __import__("datetime").datetime.utcnow().isoformat() + "Z",
            }

    def get_latency_stats(self) -> Dict[str, Any]:
        """Get inference latency statistics."""
        if not PROMETHEUS_AVAILABLE:
            return {"note": "Prometheus not installed for latency tracking."}
        return {"note": "Use prometheus endpoint for latency metrics"}

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
