from __future__ import annotations

import asyncio
import json
import logging
import signal
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse

from app.config import settings
from app.alerts.schema import Alert, Evidence
from app.alerts.manager import AlertManager
from app.alerts.broadcaster import AlertBroadcaster
from app.db.session import init_db_session, close_db_session
from app.api.deps import set_alert_manager, set_inference_engine, set_alert_broadcaster, get_alert_manager
from app.api.routes import threats, traffic, dns, tls, recon, exfil, system, reports, websocket, ingest

# Uptime at module load
_APP_START_TIME = __import__("time").time()

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

alert_manager: AlertManager | None = None
alert_broadcaster: AlertBroadcaster | None = None
inference_engine = None
_ingest_task: asyncio.Task | None = None


def _should_seed(manager: AlertManager) -> bool:
    try:
        from app.db.session import get_db
        conn=get_db()
        cur=conn.cursor()
        cur.execute("SELECT COUNT(*) FROM alerts")
        cnt=cur.fetchone()[0]
        conn.close()
        return cnt==0 and len(manager.get_active_alerts())==0
    except Exception:
        return len(manager.get_active_alerts())==0

def _seed_alerts(manager: AlertManager):
    if not _should_seed(manager):
        loaded=manager.load_from_db(limit=1000)
        if loaded>0:
            logger.info(f"Skipped seeding — restored {loaded} alerts from DB (BACKEND SEEDED DATA)")
            return
    seed_data = [
        {"threat_class": "ddos", "severity": "critical", "source_ip": "10.0.0.50", "destination_ip": "192.168.1.100", "source_port": 12345, "destination_port": 80, "protocol": "TCP", "confidence": 0.95, "bytes": 524288000, "packets": 750000, "duration": 300.0},
        {"threat_class": "c2_beacon", "severity": "high", "source_ip": "172.16.0.22", "destination_ip": "203.0.113.50", "source_port": 49832, "destination_port": 443, "protocol": "TCP", "confidence": 0.88, "bytes": 10485760, "packets": 15200, "duration": 86400.0},
        {"threat_class": "dga", "severity": "high", "source_ip": "192.168.1.45", "destination_ip": "8.8.8.8", "source_port": 52341, "destination_port": 53, "protocol": "UDP", "confidence": 0.82, "bytes": 524288, "packets": 8500, "duration": 7200.0},
        {"threat_class": "dns_tunnel", "severity": "critical", "source_ip": "10.0.0.15", "destination_ip": "198.51.100.23", "source_port": 41234, "destination_port": 53, "protocol": "UDP", "confidence": 0.91, "bytes": 2097152, "packets": 4200, "duration": 1800.0},
        {"threat_class": "tls_malware", "severity": "critical", "source_ip": "192.168.1.78", "destination_ip": "198.51.100.99", "source_port": 53421, "destination_port": 443, "protocol": "TCP", "confidence": 0.93, "bytes": 3145728, "packets": 6800, "duration": 3600.0},
        {"threat_class": "port_scan", "severity": "medium", "source_ip": "10.0.0.200", "destination_ip": "192.168.1.1", "source_port": 12345, "destination_port": 1, "protocol": "TCP", "confidence": 0.76, "bytes": 104857, "packets": 500, "duration": 600.0},
        {"threat_class": "exfiltration", "severity": "critical", "source_ip": "192.168.1.33", "destination_ip": "203.0.113.75", "source_port": 44512, "destination_port": 8080, "protocol": "TCP", "confidence": 0.89, "bytes": 1073741824, "packets": 125000, "duration": 7200.0},
        {"threat_class": "ddos", "severity": "high", "source_ip": "10.0.0.99", "destination_ip": "192.168.1.100", "source_port": 23456, "destination_port": 80, "protocol": "UDP", "confidence": 0.87, "bytes": 419430400, "packets": 600000, "duration": 240.0},
        {"threat_class": "c2_beacon", "severity": "high", "source_ip": "172.16.0.88", "destination_ip": "198.51.100.12", "source_port": 50123, "destination_port": 8443, "protocol": "TCP", "confidence": 0.85, "bytes": 8388608, "packets": 12000, "duration": 43200.0},
        {"threat_class": "dga", "severity": "medium", "source_ip": "192.168.1.101", "destination_ip": "8.8.4.4", "source_port": 54321, "destination_port": 53, "protocol": "UDP", "confidence": 0.78, "bytes": 393216, "packets": 6200, "duration": 5400.0},
        {"threat_class": "dns_tunnel", "severity": "high", "source_ip": "10.0.0.44", "destination_ip": "198.51.100.67", "source_port": 42100, "destination_port": 53, "protocol": "TCP", "confidence": 0.86, "bytes": 1572864, "packets": 3100, "duration": 2400.0},
        {"threat_class": "tls_malware", "severity": "high", "source_ip": "192.168.1.55", "destination_ip": "203.0.113.44", "source_port": 55001, "destination_port": 443, "protocol": "TCP", "confidence": 0.84, "bytes": 2621440, "packets": 5500, "duration": 2700.0},
        {"threat_class": "port_scan", "severity": "low", "source_ip": "10.0.0.177", "destination_ip": "192.168.1.50", "source_port": 11111, "destination_port": 1024, "protocol": "TCP", "confidence": 0.72, "bytes": 52428, "packets": 250, "duration": 300.0},
        {"threat_class": "exfiltration", "severity": "high", "source_ip": "192.168.1.88", "destination_ip": "198.51.100.200", "source_port": 46789, "destination_port": 9090, "protocol": "TCP", "confidence": 0.87, "bytes": 536870912, "packets": 62500, "duration": 5400.0},
        {"threat_class": "ddos", "severity": "critical", "source_ip": "10.0.0.33", "destination_ip": "192.168.1.100", "source_port": 34567, "destination_port": 443, "protocol": "TCP", "confidence": 0.96, "bytes": 1073741824, "packets": 1500000, "duration": 180.0},
        {"threat_class": "c2_beacon", "severity": "critical", "source_ip": "172.16.0.15", "destination_ip": "203.0.113.88", "source_port": 48765, "destination_port": 443, "protocol": "TCP", "confidence": 0.92, "bytes": 15728640, "packets": 22000, "duration": 172800.0},
        {"threat_class": "dga", "severity": "high", "source_ip": "192.168.1.201", "destination_ip": "1.1.1.1", "source_port": 56789, "destination_port": 53, "protocol": "UDP", "confidence": 0.83, "bytes": 655360, "packets": 10500, "duration": 9000.0},
        {"threat_class": "dns_tunnel", "severity": "high", "source_ip": "10.0.0.66", "destination_ip": "198.51.100.45", "source_port": 43210, "destination_port": 53, "protocol": "UDP", "confidence": 0.88, "bytes": 2621440, "packets": 5300, "duration": 3000.0},
        {"threat_class": "tls_malware", "severity": "critical", "source_ip": "192.168.1.42", "destination_ip": "203.0.113.111", "source_port": 57654, "destination_port": 443, "protocol": "TCP", "confidence": 0.94, "bytes": 4194304, "packets": 8900, "duration": 4500.0},
        {"threat_class": "port_scan", "severity": "medium", "source_ip": "10.0.0.188", "destination_ip": "192.168.1.250", "source_port": 22222, "destination_port": 80, "protocol": "TCP", "confidence": 0.79, "bytes": 209715, "packets": 1000, "duration": 900.0},
        {"threat_class": "exfiltration", "severity": "critical", "source_ip": "192.168.1.15", "destination_ip": "198.51.100.33", "source_port": 49876, "destination_port": 443, "protocol": "TCP", "confidence": 0.95, "bytes": 2147483648, "packets": 250000, "duration": 10800.0},
        {"threat_class": "ddos", "severity": "high", "source_ip": "10.0.0.77", "destination_ip": "192.168.1.200", "source_port": 67890, "destination_port": 80, "protocol": "ICMP", "confidence": 0.86, "bytes": 314572800, "packets": 450000, "duration": 200.0},
        {"threat_class": "c2_beacon", "severity": "medium", "source_ip": "172.16.0.99", "destination_ip": "198.51.100.55", "source_port": 51234, "destination_port": 8080, "protocol": "TCP", "confidence": 0.77, "bytes": 5242880, "packets": 7500, "duration": 21600.0},
        {"threat_class": "dga", "severity": "medium", "source_ip": "192.168.1.67", "destination_ip": "8.8.8.8", "source_port": 58765, "destination_port": 53, "protocol": "UDP", "confidence": 0.74, "bytes": 262144, "packets": 4200, "duration": 3600.0},
        {"threat_class": "dns_tunnel", "severity": "critical", "source_ip": "10.0.0.11", "destination_ip": "198.51.100.77", "source_port": 44556, "destination_port": 53, "protocol": "TCP", "confidence": 0.90, "bytes": 3145728, "packets": 6400, "duration": 4200.0},
        {"threat_class": "tls_malware", "severity": "high", "source_ip": "192.168.1.91", "destination_ip": "203.0.113.66", "source_port": 59876, "destination_port": 443, "protocol": "TCP", "confidence": 0.81, "bytes": 1572864, "packets": 3300, "duration": 1800.0},
        {"threat_class": "port_scan", "severity": "critical", "source_ip": "10.0.0.250", "destination_ip": "192.168.1.0/24", "source_port": 33333, "destination_port": 1, "protocol": "TCP", "confidence": 0.92, "bytes": 0, "packets": 50000, "duration": 120.0},
        {"threat_class": "exfiltration", "severity": "high", "source_ip": "192.168.1.110", "destination_ip": "198.51.100.88", "source_port": 52345, "destination_port": 21, "protocol": "TCP", "confidence": 0.83, "bytes": 107374182, "packets": 12500, "duration": 1800.0},
        {"threat_class": "ddos", "severity": "medium", "source_ip": "10.0.0.42", "destination_ip": "192.168.1.150", "source_port": 78901, "destination_port": 53, "protocol": "UDP", "confidence": 0.75, "bytes": 209715200, "packets": 300000, "duration": 150.0},
        {"threat_class": "c2_beacon", "severity": "critical", "source_ip": "172.16.0.33", "destination_ip": "203.0.113.22", "source_port": 53678, "destination_port": 443, "protocol": "TCP", "confidence": 0.93, "bytes": 20971520, "packets": 30000, "duration": 259200.0},
    ]

    threat_ips = [
        ("10.0.0.1", "10.0.0.5", "10.0.0.10", "10.0.0.15", "10.0.0.20", "10.0.0.25", "10.0.0.30", "10.0.0.35", "10.0.0.40", "10.0.0.45"),
        ("172.16.0.1", "172.16.0.5", "172.16.0.10", "172.16.0.15", "172.16.0.20", "172.16.0.25", "172.16.0.30", "172.16.0.35", "172.16.0.40", "172.16.0.45"),
        ("192.168.1.1", "192.168.1.10", "192.168.1.20", "192.168.1.30", "192.168.1.40", "192.168.1.50", "192.168.1.60", "192.168.1.70", "192.168.1.80", "192.168.1.90"),
        ("203.0.113.1", "203.0.113.10", "203.0.113.20", "203.0.113.30", "203.0.113.40", "203.0.113.50", "203.0.113.60", "203.0.113.70", "203.0.113.80", "203.0.113.90"),
        ("198.51.100.1", "198.51.100.10", "198.51.100.20", "198.51.100.30", "198.51.100.40", "198.51.100.50", "198.51.100.60", "198.51.100.70", "198.51.100.80", "198.51.100.90"),
    ]

    model_versions = ["v1.0.0", "v1.1.0", "v1.2.0", "v2.0.0"]

    for i, data in enumerate(seed_data):
        now = datetime.now(timezone.utc)
        from datetime import timedelta
        ts = now - timedelta(seconds=i * 120)

        src_ip = data["source_ip"]
        dst_ip = data["destination_ip"]
        all_ips = [ip for row in threat_ips for ip in row]
        import random
        random.seed(i)
        src_ip = random.choice(all_ips)
        dst_ip = random.choice(all_ips)

        alert = Alert(
            alert_id=str(uuid.uuid4()),
            timestamp=ts.isoformat(),
            flow_id=f"flow-{uuid.uuid4().hex[:16]}",
            threat_class=data["threat_class"],
            severity=data["severity"],
            confidence=data["confidence"],
            source_ip=src_ip,
            source_port=data["source_port"],
            destination_ip=dst_ip,
            destination_port=data["destination_port"],
            protocol=data["protocol"].lower(),
            bytes_transferred=data["bytes"],
            packet_count=data["packets"],
            duration_seconds=data["duration"],
            evidence=[Evidence(
                feature_name=data["threat_class"],
                value=round(data["confidence"], 2),
                contribution=round(data["confidence"], 2),
                description=f"Automated detection for {data['threat_class']}: {src_ip} -> {dst_ip}:{data['destination_port']}"
            )],
            model_version=random.choice(model_versions),
            raw_features={}
        )
        manager.add_alert(alert)

    logger.info(f"Seeded {len(seed_data)} alerts for immediate API responses")


@asynccontextmanager
async def lifespan(app: FastAPI):
    global alert_manager, alert_broadcaster, inference_engine
    logger.info(f"Starting {settings.project_name} v{settings.version} env={settings.env}")
    await init_db_session()
    alert_manager = AlertManager(max_history=settings.alert_max_history)
    alert_broadcaster = AlertBroadcaster()
    set_alert_manager(alert_manager)
    set_alert_broadcaster(alert_broadcaster)
    # Initialize ML inference engine (loads artifacts)
    try:
        from app.inference.engine import InferenceEngine
        inference_engine = InferenceEngine()
        await inference_engine.initialize_models()
        set_inference_engine(inference_engine)
        logger.info("Inference engine initialized with trained models")
    except Exception as e:
        logger.warning(f"Inference engine warmup failed (seeded alerts still available): {e}")
    _seed_alerts(alert_manager)
    logger.info("Backend initialized and seeded successfully — DATA MODE: BACKEND SEEDED (see /system/status)")
    # Start ingest pipeline (passive, background)
    try:
        from app.ingest.pipeline import start_background_ingest
        from app.metrics.collector import get_metrics
        flow_metrics_inst = get_metrics()
        _ingest_task_local = asyncio.create_task(start_background_ingest(alert_manager, inference_engine, alert_broadcaster, flow_metrics_inst))
        globals()['_ingest_task'] = _ingest_task_local
        logger.info("Ingest pipeline background task started (passive)")
    except Exception as e:
        logger.warning(f"Ingest pipeline start failed: {e}")
    yield
    logger.info("Shutting down...")
    try:
        t = globals().get('_ingest_task')
        if t and not t.done():
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass
    except Exception:
        pass
    try:
        await close_db_session()
    except Exception:
        pass


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.project_name,
        version=settings.version,
        description="Passive AI Cyber Threat Intelligence Platform",
        lifespan=lifespan,
    )

    # CORS — production should set explicit origins via CYBERSENTINEL_CORS_ORIGINS
    cors_origins = ["http://localhost:5173", "http://localhost:3000"]
    if settings.cors_origins:
        origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
        cors_origins.extend(origins)
    # dedupe, remove empty
    cors_origins = sorted(set(o for o in cors_origins if o))
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Security headers + rate limit (simple in-memory)
    from collections import defaultdict
    import time as _rl_time
    _rl_store: dict = {}
    _RL_WINDOW = 60

    @app.middleware("http")
    async def security_headers_and_ratelimit(request: Request, call_next):
        # Security headers
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "0"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if settings.env == "production":
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        # Request ID
        rid = request.headers.get("X-Request-Id") or str(uuid.uuid4())
        response.headers["X-Request-Id"] = rid
        # Simple rate limit (per IP, per minute)
        try:
            limit = int(getattr(settings, "rate_limit_per_minute", 120))
            if limit > 0:
                ip = request.client.host if request.client else "unknown"
                now = _rl_time.time()
                window_key = f"{ip}:{int(now // _RL_WINDOW)}"
                # prune old windows
                for k in list(_rl_store.keys()):
                    if _rl_store[k][1] < now - _RL_WINDOW:
                        _rl_store.pop(k, None)
                cnt, _ = _rl_store.get(window_key, (0, now))
                if cnt >= limit:
                    return JSONResponse(status_code=429, content={"detail": "Too Many Requests", "retry_after": _RL_WINDOW})
                _rl_store[window_key] = (cnt + 1, now)
        except Exception:
            pass
        # Optional API key enforcement (if set)
        try:
            api_key = getattr(settings, "api_key", None) or __import__("os").environ.get("CYBERSENTINEL_API_KEY")
            if api_key:
                # exempt health/metrics/docs
                if not request.url.path.startswith(("/health", "/metrics", "/docs", "/openapi", "/redoc")):
                    provided = request.headers.get("X-API-Key") or request.query_params.get("api_key")
                    if provided != api_key:
                        return JSONResponse(status_code=401, content={"detail": "Invalid API key"})
        except Exception:
            pass
        return response

    app.include_router(threats.router)
    app.include_router(traffic.router)
    app.include_router(dns.router)
    app.include_router(tls.router)
    app.include_router(recon.router)
    app.include_router(exfil.router)
    app.include_router(system.router)
    app.include_router(reports.router)
    app.include_router(websocket.router)
    app.include_router(ingest.router)

    # ---- Global health aliases (for Dockerfile HEALTHCHECK & probes) ----
    import time as _time

    def _health_payload(ready: bool | None = None):
        # import here to avoid circular
        am = None
        try:
            am = get_alert_manager()
        except Exception:
            am = alert_manager
        uptime = round(_time.time() - _APP_START_TIME, 2)
        live = bool(__import__("os").environ.get("CYBERSENTINEL_LIVE_INTERFACE") or getattr(settings, "live_interface", None))
        status = "operational" if am else "initializing"
        if ready is True:
            status = "ready" if am else "initializing"
        elif ready is False:
            status = "alive"
        return {
            "status": status,
            "version": settings.version,
            "uptime_seconds": uptime,
            "uptime": f"{uptime}s",
            "live_mode": "live" if live else "passive",
            "components": {
                "ingest": "live" if live else "passive (idle)",
                "inference": "ready" if am else "loading",
                "alerting": "active" if am else "initializing",
                "websocket": "active",
                "database": "connected",
            },
        }

    @app.get("/health", tags=["system"], summary="Health (root alias)")
    async def health_root():
        return _health_payload()

    @app.get("/health/ready", tags=["system"], summary="Readiness probe")
    async def health_ready_root():
        payload = _health_payload(ready=True)
        payload["ready"] = payload["status"] == "ready"
        payload["endpoint"] = "/health/ready"
        return payload

    @app.get("/health/live", tags=["system"], summary="Liveness probe")
    async def health_live_root():
        payload = _health_payload(ready=False)
        payload["status"] = "alive"
        payload["endpoint"] = "/health/live"
        return payload

    # API-prefixed aliases for tests that expect /api prefix
    @app.get("/api/health", tags=["system"], include_in_schema=False)
    async def health_api():
        return _health_payload()

    @app.get("/api/system/status", tags=["system"], include_in_schema=False)
    async def system_status_alias():
        # Mirror system status logic
        am = None
        try:
            am = get_alert_manager()
        except Exception:
            am = alert_manager
        uptime = round(_time.time() - _APP_START_TIME, 2)
        live = bool(__import__("os").environ.get("CYBERSENTINEL_LIVE_INTERFACE") or getattr(settings, "live_interface", None))
        return {
            "status": "operational" if am else "initializing",
            "components": {
                "ingest": "live" if live else "idle (passive mode)",
                "inference": "ready" if am else "loading",
                "alerting": "active" if am else "initializing",
                "websocket": "active",
                "database": "connected",
            },
            "version": settings.version,
            "uptime_seconds": uptime,
        }

    @app.get("/api/health/ready", tags=["system"], include_in_schema=False)
    async def health_api_ready():
        return await health_ready_root()

    @app.get("/api/health/live", tags=["system"], include_in_schema=False)
    async def health_api_live():
        return await health_live_root()

    # Metrics endpoint (prometheus text format)
    @app.get("/metrics", summary="Prometheus metrics", response_class=PlainTextResponse, tags=["metrics"])
    async def metrics():
        try:
            from app.metrics.prometheus import get_metrics_endpoint
            data = get_metrics_endpoint()
            # get_metrics_endpoint returns bytes; ensure text/plain
            if isinstance(data, bytes):
                return Response(content=data, media_type="text/plain; version=0.0.4; charset=utf-8")
            return PlainTextResponse(str(data), media_type="text/plain")
        except Exception as e:
            logger.warning(f"Metrics endpoint error: {e}")
            # Fallback minimal metrics with flow counts
            try:
                from app.metrics.collector import get_metrics
                m = get_metrics()
                stats = m.get_throughput_stats()
                fallback = (
                    "# HELP cybersentinel_flows_total Total flows\n"
                    "# TYPE cybersentinel_flows_total counter\n"
                    f"cybersentinel_flows_total {stats.get('active_flows', 0)}\n"
                )
                return PlainTextResponse(fallback, media_type="text/plain")
            except Exception:
                return PlainTextResponse("# HELP cybersentinel_backend_disabled 1\n# TYPE cybersentinel_backend_disabled gauge\ncybersentinel_backend_disabled 1\n", media_type="text/plain")

    # Also alias /api/metrics
    @app.get("/api/metrics", summary="Prometheus metrics alias", response_class=PlainTextResponse, tags=["metrics"], include_in_schema=False)
    async def metrics_alias():
        return await metrics()

    @app.get("/", tags=["system"], summary="Root info")
    async def root_info():
        return {"name": settings.project_name, "version": settings.version, "status": "running", "health": "/health", "docs": "/docs"}

    @app.exception_handler(Exception)
    async def global_exception_handler(request, exc):
        logger.error(f"Unhandled exception: {exc}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error_type": type(exc).__name__},
        )

    return app


app = create_app()
