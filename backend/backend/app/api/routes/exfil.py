from fastapi import APIRouter, Depends, Query
from typing import Any, List
from app.api.deps import get_alert_manager

router = APIRouter(prefix="/exfil", tags=["exfil"])


@router.get("/anomalies", summary="Exfiltration detections")
async def get_exfil_anomalies(limit: int = Query(100, ge=1, le=1000), alert_manager: Any = Depends(get_alert_manager)):
    if not alert_manager:
        return []
    alerts = [a for a in alert_manager.get_active_alerts() if a.threat_class == "exfiltration"]
    alerts.sort(key=lambda a: a.bytes_transferred, reverse=True)
    return [a.model_dump() for a in alerts[:limit]]
