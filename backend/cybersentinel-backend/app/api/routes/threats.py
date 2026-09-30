from fastapi import APIRouter, Depends, Query, Path, HTTPException
from typing import List, Optional, Any

from app.alerts.schema import Alert
from app.alerts.manager import AlertManager
from app.api.deps import get_alert_manager

router = APIRouter(prefix="/threats", tags=["threats"])


@router.get("/", response_model=List[Alert], summary="Paginated threat list")
async def list_threats(
    limit: int = Query(100, ge=1, le=1000),
    severity: Optional[str] = Query(None),
    threat_class: Optional[str] = Query(None),
    alert_manager: Any = Depends(get_alert_manager),
):
    if not alert_manager:
        return []
    alerts = alert_manager.get_active_alerts()
    filtered = alerts
    if severity:
        filtered = [a for a in filtered if a.severity == severity]
    if threat_class:
        filtered = [a for a in filtered if a.threat_class == threat_class]
    filtered.sort(key=lambda a: a.timestamp, reverse=True)
    return filtered[:limit]


@router.get("/{alert_id}", response_model=Alert, summary="Get full alert detail")
async def get_threat_detail(
    alert_id: str = Path(...),
    alert_manager: Any = Depends(get_alert_manager),
):
    if not alert_manager:
        raise HTTPException(status_code=404, detail="Alert manager not initialized")
    for alert in alert_manager.get_active_alerts():
        if alert.alert_id == alert_id:
            return alert
    raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
