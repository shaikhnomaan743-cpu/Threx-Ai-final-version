from fastapi import APIRouter, Depends, HTTPException
from typing import Any
from pydantic import BaseModel
import time

from app.api.deps import get_alert_manager, get_inference_engine
from app.ingest.pipeline import get_ingest_status, ingest_pcap_file, ingest_lab_flow

router = APIRouter(prefix="/ingest", tags=["ingest"])

class FlowInjectRequest(BaseModel):
    src_ip: str = "192.0.2.10"
    dst_ip: str = "198.51.100.20"
    src_port: int = 54321
    dst_port: int = 80
    protocol: str = "tcp"
    packet_count: int = 100
    bytes_transferred: int = 50000
    duration_seconds: float = 2.0
    raw_features: dict = {}
    # alternate keys for convenience
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None

@router.get("/status", summary="Ingest pipeline status (DATA SOURCE, interface, counts)")
async def ingest_status():
    status = get_ingest_status()
    return status

@router.post("/flow", summary="Inject a single lab flow through FULL pipeline (packet→flow→inference→alert→WS→DB)")
async def inject_flow(req: FlowInjectRequest, alert_manager: Any = Depends(get_alert_manager)):
    if not alert_manager:
        raise HTTPException(status_code=503, detail="Alert manager not ready")
    try:
        from app.api.deps import get_inference_engine, get_alert_broadcaster
        from app.metrics.collector import get_metrics
        inference_engine = get_inference_engine()
        if not inference_engine:
            raise HTTPException(status_code=503, detail="Inference engine not ready")
        from app.alerts.broadcaster import AlertBroadcaster
        broadcaster = get_alert_broadcaster()
        if not broadcaster:
            broadcaster = AlertBroadcaster()
        metrics = get_metrics()
        flow_dict = req.model_dump()
        # normalize alternate keys
        if flow_dict.get("source_ip"):
            flow_dict["src_ip"] = flow_dict["source_ip"]
        if flow_dict.get("destination_ip"):
            flow_dict["dst_ip"] = flow_dict["destination_ip"]
        if flow_dict.get("source_port"):
            flow_dict["src_port"] = flow_dict["source_port"]
        if flow_dict.get("destination_port"):
            flow_dict["dst_port"] = flow_dict["destination_port"]
        alerts = await ingest_lab_flow(flow_dict, alert_manager, inference_engine, broadcaster, metrics)
        return {
            "status": "processed",
            "flow": flow_dict,
            "alerts_generated": len(alerts),
            "alerts": [a.model_dump(mode="json") if hasattr(a, "model_dump") else a.dict() for a in alerts],
            "ingest_status": get_ingest_status(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Flow injection failed: {e}")

@router.post("/pcap", summary="Replay a PCAP/JSON file through pipeline")
async def replay_pcap(payload: dict, alert_manager: Any = Depends(get_alert_manager)):
    filepath = payload.get("filepath") or payload.get("path") or "data/pcaps/mixed/sample_flow.json"
    if not alert_manager:
        raise HTTPException(status_code=503, detail="Alert manager not ready")
    try:
        from app.api.deps import get_inference_engine, get_alert_broadcaster
        from app.metrics.collector import get_metrics
        inference_engine = get_inference_engine()
        broadcaster = get_alert_broadcaster()
        metrics = get_metrics()
        if not inference_engine:
            raise HTTPException(status_code=503, detail="Inference engine not ready")
        count = await ingest_pcap_file(filepath, alert_manager, inference_engine, broadcaster, metrics, data_source="PCAP_REPLAY")
        return {"status":"replayed","filepath":filepath,"flows_processed":count, "ingest_status": get_ingest_status()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/pcap", summary="List available PCAP replay files")
async def list_pcap():
    import os
    from app.config import settings
    candidates = []
    for root in [settings.pcap_dir, "data/pcaps", os.path.join(os.path.dirname(__file__), "..", "..", "data", "pcaps")]:
        if os.path.isdir(root):
            for dirpath, _, files in os.walk(root):
                for f in files:
                    if f.endswith((".pcap",".json")):
                        candidates.append(os.path.join(dirpath, f))
    return {"pcap_dir": settings.pcap_dir, "files": candidates[:20]}
