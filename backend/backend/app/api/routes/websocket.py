from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import asyncio
import json
import logging

logger = logging.getLogger(__name__)
router = APIRouter(tags=["websocket"])


class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket connected. Total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(f"WebSocket disconnected. Total: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        dead = []
        for conn in self.active_connections:
            try:
                await conn.send_json(message)
            except Exception:
                dead.append(conn)
        for d in dead:
            self.disconnect(d)


manager = ConnectionManager()


@router.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket):
    await manager.connect(websocket)
    # send recent alerts on connect
    try:
        from app.api.deps import get_alert_manager
        am = get_alert_manager()
        if am:
            recent = am.get_active_alerts()[-5:]
            for a in recent:
                try:
                    await websocket.send_json({"type":"alert","data": a.model_dump(mode="json") if hasattr(a,"model_dump") else a.dict(), "source":"replay"})
                except Exception:
                    pass
    except Exception:
        pass
    try:
        while True:
            # keep alive, also handle client pings
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30)
                await websocket.send_json({"type": "ack", "data": data})
            except asyncio.TimeoutError:
                await websocket.send_json({"type":"ping"})
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)


@router.websocket("/ws/metrics")
async def ws_metrics(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await asyncio.sleep(2)
            try:
                from app.ingest.pipeline import get_ingest_status
                from app.metrics.collector import get_metrics
                from app.api.deps import get_alert_manager
                pipeline = get_ingest_status()
                m = get_metrics()
                stats = m.get_throughput_stats()
                am = get_alert_manager()
                active = len(am.get_active_alerts()) if am else 0
                await websocket.send_json({
                    "type": "metrics",
                    "flows_per_second": stats.get("flows_per_sec", 0),
                    "packets_per_second": stats.get("packets_per_sec", 0),
                    "bytes_per_second": stats.get("bytes_per_sec", 0),
                    "active_alerts": active,
                    "total_flows": pipeline.get("flows_processed", 0),
                    "packets_received": pipeline.get("packets_received", 0),
                    "alerts_generated": pipeline.get("alerts_generated", 0),
                    "data_source": pipeline.get("data_source"),
                    "live_interface": pipeline.get("live_interface"),
                    "return_path": pipeline.get("return_path", "NONE"),
                    "inference_latency_ms": pipeline.get("inference_latency_ms", 0),
                })
            except Exception as e:
                await websocket.send_json({"type":"metrics","error": str(e)})
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)


async def broadcast_alert(alert: dict):
    await manager.broadcast({"type": "alert", "data": alert})
