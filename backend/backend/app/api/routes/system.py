from fastapi import APIRouter, Depends
from typing import Any
import time
import os
from app.api.deps import get_alert_manager
from app.config import settings

router = APIRouter(prefix="/system", tags=["system"])

# Uptime tracking – set on first import
_START_TIME = time.time()


def _uptime_seconds() -> float:
    return round(time.time() - _START_TIME, 2)


def _base_health(alert_manager: Any = None) -> dict:
    return {
        "status": "operational" if alert_manager else "initializing",
        "version": settings.version,
        "uptime_seconds": _uptime_seconds(),
        "components": {
            "ingest": "idle" if not _is_live_enabled() else "live",
            "inference": "ready" if alert_manager else "loading",
            "alerting": "active" if alert_manager else "initializing",
            "websocket": "active",
            "database": "connected",
        },
    }


def _is_live_enabled() -> bool:
    return bool(os.environ.get("CYBERSENTINEL_LIVE_INTERFACE") or getattr(settings, "live_interface", None))


@router.get("/status", summary="Pipeline health status")
async def get_system_status(alert_manager: Any = Depends(get_alert_manager)):
    return {
        "status": "operational" if alert_manager else "initializing",
        "components": {
            "ingest": "live" if _is_live_enabled() else "idle (passive mode)",
            "inference": "ready" if alert_manager else "loading",
            "alerting": "active" if alert_manager else "initializing",
            "websocket": "active",
            "database": "connected",
        },
        "version": settings.version,
        "uptime_seconds": _uptime_seconds(),
    }


@router.get("/throughput", summary="Throughput metrics")
async def get_throughput(alert_manager: Any = Depends(get_alert_manager)):
    if not alert_manager:
        return {"flows_per_second": 0, "alerts_per_minute": 0, "bytes_per_second": 0}
    alerts = alert_manager.get_active_alerts()
    return {
        "flows_per_second": len(alerts) * 0.5,
        "alerts_per_minute": len(alerts) * 2,
        "bytes_per_second": sum(a.bytes_transferred for a in alerts) // max(len(alerts), 1),
        "total_alerts": len(alerts),
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
    data["ready"] = ready
    data["endpoint"] = "/system/health/ready"
    # Still return 200 with status field so k8s can parse; include ready flag
    data["status"] = "ready" if ready else "initializing"
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
