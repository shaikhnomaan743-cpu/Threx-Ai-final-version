from fastapi import APIRouter, Depends, Query
from typing import Any, List
from app.api.deps import get_alert_manager

router = APIRouter(prefix="/tls", tags=["tls"])


@router.get("/fingerprints", summary="JA3/JA4 fingerprint lookups")
async def get_tls_fingerprints(limit: int = Query(100, ge=1, le=1000), alert_manager: Any = Depends(get_alert_manager)):
    if not alert_manager:
        return []
    alerts = [a for a in alert_manager.get_active_alerts() if a.threat_class == "tls_malware"]
    alerts.sort(key=lambda a: a.confidence, reverse=True)
    return [a.model_dump() for a in alerts[:limit]]


@router.get("/malware", summary="TLS malware detections")
async def get_tls_malware(limit: int = Query(100, ge=1, le=1000), alert_manager: Any = Depends(get_alert_manager)):
    if not alert_manager:
        return []
    alerts = [a for a in alert_manager.get_active_alerts() if a.threat_class == "tls_malware"]
    alerts.sort(key=lambda a: a.timestamp, reverse=True)
    return [a.model_dump() for a in alerts[:limit]]
