from fastapi import APIRouter, Depends, Query
from typing import Any, Optional, List
from app.api.deps import get_alert_manager

router = APIRouter(prefix="/traffic", tags=["traffic"])


@router.get("/stats", summary="Flow statistics")
async def get_flow_stats(alert_manager: Any = Depends(get_alert_manager)):
    if not alert_manager:
        return {"total_flows": 0, "active_flows": 0, "total_bytes": 0, "total_packets": 0}
    alerts = alert_manager.get_active_alerts()
    total_bytes = sum(a.bytes_transferred for a in alerts)
    total_packets = sum(a.packet_count for a in alerts)
    return {
        "total_flows": len(alerts),
        "active_flows": len(alerts),
        "total_bytes": total_bytes,
        "total_packets": total_packets,
        "avg_bytes_per_flow": total_bytes // max(len(alerts), 1),
        "avg_packets_per_flow": total_packets // max(len(alerts), 1),
    }


@router.get("/top-talkers", summary="Top IPs by traffic")
async def get_top_talkers(
    limit: int = Query(10, ge=1, le=100),
    alert_manager: Any = Depends(get_alert_manager),
):
    if not alert_manager:
        return []
    from collections import defaultdict
    alerts = alert_manager.get_active_alerts()
    ip_bytes: dict[str, int] = defaultdict(int)
    for a in alerts:
        ip_bytes[a.source_ip] += a.bytes_transferred
    sorted_ips = sorted(ip_bytes.items(), key=lambda x: x[1], reverse=True)[:limit]
    return [{"ip": ip, "bytes": b} for ip, b in sorted_ips]


@router.get("/protocols", summary="Protocol distribution")
async def get_protocol_distribution(alert_manager: Any = Depends(get_alert_manager)):
    if not alert_manager:
        return []
    from collections import defaultdict
    alerts = alert_manager.get_active_alerts()
    proto_count: dict[str, int] = defaultdict(int)
    for a in alerts:
        proto_count[a.protocol] += 1
    return [{"protocol": p, "count": c} for p, c in sorted(proto_count.items(), key=lambda x: x[1], reverse=True)]
