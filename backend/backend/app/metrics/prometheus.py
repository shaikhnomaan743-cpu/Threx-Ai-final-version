from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

try:
    from prometheus_client import Counter, Histogram, generate_latest, start_http_server  # type: ignore
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False


def start_prometheus_server(port: int = 9090):
    """Start Prometheus metrics HTTP server.

    Separate from FastAPI /metrics endpoint; optional sidecar on :9090.
    """
    if not PROMETHEUS_AVAILABLE:
        import warnings
        warnings.warn(
            "prometheus_client not installed; skipping prometheus server start",
            ImportWarning,
        )
        return

    try:
        start_http_server(port)
        logger.info(f"Prometheus metrics server started on port {port}")
    except OSError as e:
        logger.warning(f"Prometheus server failed to start on {port}: {e}")
    except Exception as e:
        logger.warning(f"Prometheus server error: {e}")


def get_metrics_endpoint() -> bytes:
    """Generate Prometheus metrics endpoint output.

    Delegates to collector's prometheus_text for unified flow counts.
    Returns bytes in Prometheus text format for /metrics endpoint.
    """
    try:
        from app.metrics.collector import get_metrics
        return get_metrics().prometheus_text()
    except Exception as e:
        logger.debug(f"collector prometheus_text failed: {e}")

    if not PROMETHEUS_AVAILABLE:
        return b"# HELP cybersentinel_backend_disabled Prometheus client not available\n# TYPE cybersentinel_backend_disabled gauge\ncybersentinel_backend_disabled 1\n"

    try:
        return generate_latest()  # type: ignore
    except Exception as e:
        logger.warning(f"generate_latest failed: {e}")
        return b"# HELP cybersentinel_backend_error Metrics generation failed\n# TYPE cybersentinel_backend_error gauge\ncybersentinel_backend_error 1\n"
