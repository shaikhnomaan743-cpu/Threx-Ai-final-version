from fastapi import APIRouter, Depends
from typing import Any
import time
import os
from app.api.deps import get_alert_manager, engine_ready, get_engine_error
from app.config import settings

router = APIRouter(prefix="/system", tags=["system"])

# Uptime tracking – set on first import
_START_TIME = time.time()


def _uptime_seconds() -> float:
    return round(time.time() - _START_TIME, 2)


def _base_health(alert_manager: Any = None) -> dict:
    # `inference` must reflect the engine, not the alert manager. Reporting it
    # from alert_manager meant a dead engine still showed "ready".
    eng_ok = engine_ready()
    payload = {
        "status": ("operational" if eng_ok else "degraded") if alert_manager else "initializing",
        "version": settings.version,
        "uptime_seconds": _uptime_seconds(),
        "detection_active": eng_ok,
        "components": {
            "ingest": "idle" if not _is_live_enabled() else "live",
            "inference": "ready" if eng_ok else "UNAVAILABLE",
            "alerting": "active" if alert_manager else "initializing",
            "websocket": "active",
            "database": "connected",
        },
    }
    if not eng_ok:
        payload["degraded_reason"] = get_engine_error() or "inference engine not initialised"
    return payload


def _is_live_enabled() -> bool:
    return bool(os.environ.get("CYBERSENTINEL_LIVE_INTERFACE") or getattr(settings, "live_interface", None))


@router.get("/status", summary="Pipeline health status")
async def get_system_status(alert_manager: Any = Depends(get_alert_manager)):
    data = _base_health(alert_manager)
    data["components"]["ingest"] = "live" if _is_live_enabled() else "idle (passive mode)"
    return data


@router.get("/throughput", summary="Throughput metrics")
async def get_throughput(alert_manager: Any = Depends(get_alert_manager)):
    """Real measured throughput.

    This previously returned `flows_per_second = len(alerts) * 0.5` and
    `alerts_per_minute = len(alerts) * 2` — arithmetic on the size of the alert
    table, not a measurement of anything. It now reads the same FlowMetrics
    counters as /api/v1/metrics/throughput, so every surface quotes one number.
    """
    from app.metrics.collector import get_metrics
    m = get_metrics()
    tp = m.get_throughput_stats()
    lat = m.get_latency_stats()
    q = m.get_queue_stats()
    return {
        "flows_per_second": tp.get("flows_per_sec", 0.0),
        "peak_flows_per_second": tp.get("peak_flows_per_sec", 0.0),
        "packets_per_second": tp.get("packets_per_sec", 0.0),
        "bytes_per_second": tp.get("bytes_per_sec", 0.0),
        "p50_latency_ms": lat.get("p50_ms", 0.0),
        "p95_latency_ms": lat.get("p95_ms", 0.0),
        "p99_latency_ms": lat.get("p99_ms", 0.0),
        "dropped_flows": q.get("dropped_flows", 0),
        "queue_depth": q.get("queue_depth", 0),
        "total_flows": tp.get("total_flows", 0),
        "total_alerts": len(alert_manager.get_active_alerts()) if alert_manager else 0,
    }


# --- Health probes (production-ready) ---

@router.get("/health", summary="Liveness + basic health")
async def health(alert_manager: Any = Depends(get_alert_manager)):
    """Main health endpoint at /system/health.

    Also aliased to /health at root level (see main.py).
    """
    data = _base_health(alert_manager)
    data["endpoint"] = "/system/health"
    data["live_mode"] = "live" if _is_live_enabled() else "passive"
    if not _is_live_enabled():
        data["note"] = "LIVE INGEST requires CYBERSENTINEL_LIVE_INTERFACE env var (passive mode)"
    return data


@router.get("/health/ready", summary="Readiness probe")
async def health_ready(alert_manager: Any = Depends(get_alert_manager)):
    """Readiness: returns 200 only if alert_manager & inference are ready."""
    ready = alert_manager is not None
    data = _base_health(alert_manager)
    data["ready"] = ready and engine_ready()
    data["endpoint"] = "/system/health/ready"
    # Still return 200 with status field so k8s can parse; include ready flag
    data["status"] = "ready" if (ready and engine_ready()) else ("degraded" if ready else "initializing")
    return data


@router.get("/health/live", summary="Liveness probe")
async def health_live():
    """Liveness: always 200 if process is up, even if not ready."""
    return {
        "status": "alive",
        "version": settings.version,
        "uptime_seconds": _uptime_seconds(),
        "components": {
            "process": "running",
            "ingest": "live" if _is_live_enabled() else "passive",
        },
        "live_mode": "live" if _is_live_enabled() else "passive",
        "endpoint": "/system/health/live",
    }


@router.get("/health/detailed", summary="Detailed health with dependencies")
async def health_detailed(alert_manager: Any = Depends(get_alert_manager)):
    """Detailed health for debugging."""
    data = _base_health(alert_manager)
    try:
        from app.metrics.collector import get_metrics
        m = get_metrics()
        throughput = m.get_throughput_stats()
        data["metrics"] = throughput
    except Exception:
        data["metrics"] = {"note": "metrics unavailable"}
    data["env"] = settings.env
    return data
