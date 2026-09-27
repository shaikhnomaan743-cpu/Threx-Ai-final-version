"""Live telemetry and analytics endpoints (API v1).

Every number served here is measured inside this process: flow counters over a
real wall-clock interval, a real latency window, psutil for CPU/memory, and the
actual asyncio queue depth. Nothing is a stored constant and nothing is
synthesised. If a source is genuinely unavailable (psutil missing), the payload
says so instead of substituting a plausible value.

These replace the client-side Math.random() generators the dashboard used to
draw its charts with.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status

from app.api.deps import get_alert_manager, engine_ready, get_engine_error
from app.metrics.collector import get_metrics

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["telemetry"])


@router.get("/metrics/throughput", summary="Live pipeline telemetry")
async def throughput_telemetry() -> dict[str, Any]:
    """Real-time throughput, latency, queue and resource metrics.

    This is the single source of truth for the dashboard's headline numbers.
    """
    m = get_metrics()
    tp = m.get_throughput_stats()
    lat = m.get_latency_stats()
    q = m.get_queue_stats()
    res = m.get_resource_stats()

    try:
        from app.ingest.pipeline import get_queue_depth, get_ingest_status
        live_depth = get_queue_depth()
        ingest = get_ingest_status()
    except Exception:
        live_depth = q.get("queue_depth", 0)
        ingest = {}

    return {
        "flows_per_sec": tp.get("flows_per_sec", 0.0),
        "peak_flows_per_sec": tp.get("peak_flows_per_sec", 0.0),
        "packets_per_sec": tp.get("packets_per_sec", 0.0),
        "bytes_per_sec": tp.get("bytes_per_sec", 0.0),
        "total_flows": tp.get("total_flows", 0),
        "total_packets": tp.get("total_packets", 0),
        "total_bytes": tp.get("total_bytes", 0),
        "latency": lat,
        "queue": {
            "depth": live_depth,
            "dropped_flows": q.get("dropped_flows", 0),
        },
        "alerts_generated": q.get("total_alerts", 0),
        "resources": res,
        "detection_active": engine_ready(),
        "degraded_reason": None if engine_ready() else (get_engine_error() or "engine unavailable"),
        "data_source": ingest.get("data_source"),
        "return_path": "NONE",
        "uptime_seconds": tp.get("uptime_seconds", 0.0),
        "timestamp": tp.get("timestamp"),
        "pipeline": _pipeline_block(),
    }


def _pipeline_block() -> dict[str, Any]:
    """Multi-core pipeline health: mode, worker count and every loss counter.
    In multi-core mode `latency` above is UDP receipt -> detection done."""
    try:
        from app.ingest.pipeline import _parallel_state
    except Exception:
        _parallel_state = {}
    pipe, pump = _parallel_state.get("pipe"), _parallel_state.get("pump")
    if pipe is None:
        return {"mode": "single_process", "latency_basis": "inference only"}
    r = _parallel_state.get("receiver") or {}
    return {
        "mode": "multi_core",
        "workers": pipe.n, "dst_aggregators": len(pipe.agg_qs),
        "latency_basis": "UDP receipt -> detection done",
        "records_received": r.get("records", 0),
        "loss": {"exporter_seq_gap_records": r.get("seq_gap_records", 0),
                 "queue_drops_messages": r.get("queue_drops_messages", 0),
                 "unknown_template_sets": r.get("unknown_template_sets", 0),
                 "malformed_datagrams": r.get("malformed", 0)},
        "alerts": dict(pump.stats) if pump is not None else {},
    }


@router.get("/analytics/time-series", summary="Bucketed flow/protocol time series")
async def time_series(
    buckets: int = Query(60, ge=5, le=300, description="Number of time buckets"),
    bucket_seconds: int = Query(1, ge=1, le=60, description="Seconds per bucket"),
) -> dict[str, Any]:
    """Time-bucketed flow, packet and byte counts actually observed.

    Buckets with no traffic are returned as zeros rather than omitted, so the
    chart shows real quiet periods instead of interpolating over them.
    """
    m = get_metrics()
    series = m.get_flow_history(buckets=buckets, bucket_seconds=bucket_seconds)
    tp = m.get_throughput_stats()
    observed = sum(b["flows"] for b in series)
    return {
        "buckets": buckets,
        "bucket_seconds": bucket_seconds,
        "series": series,
        "protocol_distribution": tp.get("protocol_distribution", {}),
        "observed_flows_in_window": observed,
        "window_empty": observed == 0,
        "timestamp": tp.get("timestamp"),
    }


def _alert_payload(a: Any) -> dict[str, Any]:
    if hasattr(a, "model_dump"):
        return a.model_dump(mode="json")
    if hasattr(a, "dict"):
        return a.dict()
    return dict(a)


@router.get("/alerts/recent", summary="Recent alerts with full ML breakdown")
async def recent_alerts(
    limit: int = Query(50, ge=1, le=1000),
    severity: str | None = Query(None),
    threat_class: str | None = Query(None),
    alert_manager: Any = Depends(get_alert_manager),
) -> dict[str, Any]:
    if alert_manager is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "alert_store_unavailable"},
        )
    alerts = alert_manager.get_active_alerts()
    if severity:
        alerts = [a for a in alerts if str(a.severity).lower() == severity.lower()]
    if threat_class:
        alerts = [a for a in alerts if str(a.threat_class).lower() == threat_class.lower()]
    alerts = alerts[:limit]
    return {
        "count": len(alerts),
        "detection_active": engine_ready(),
        "alerts": [_alert_payload(a) for a in alerts],
    }


@router.get("/alerts/{alert_id}", summary="Single alert with evidence breakdown")
async def alert_detail(
    alert_id: str,
    alert_manager: Any = Depends(get_alert_manager),
) -> dict[str, Any]:
    if alert_manager is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "alert_store_unavailable"},
        )
    for a in alert_manager.get_active_alerts():
        if getattr(a, "alert_id", None) == alert_id:
            return _alert_payload(a)
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={"error": "alert_not_found", "alert_id": alert_id},
    )


def _class_alerts(alert_manager: Any, classes: set[str]) -> list:
    return [a for a in alert_manager.get_active_alerts()
            if str(a.threat_class).lower() in classes]


def _evidence_value(alert: Any, name: str, default: float = 0.0) -> float:
    for e in getattr(alert, "evidence", []) or []:
        if getattr(e, "feature_name", None) == name:
            try:
                return float(getattr(e, "value", default))
            except (TypeError, ValueError):
                return default
    raw = getattr(alert, "raw_features", None) or {}
    try:
        return float(raw.get(name, default))
    except (TypeError, ValueError):
        return default


@router.get("/analytics/dns", summary="DNS detector telemetry")
async def dns_analytics(alert_manager: Any = Depends(get_alert_manager)) -> dict[str, Any]:
    if alert_manager is None:
        raise HTTPException(status_code=503, detail={"error": "alert_store_unavailable"})
    dga = _class_alerts(alert_manager, {"dga"})
    tunnel = _class_alerts(alert_manager, {"dns_tunnel"})
    entropies = [_evidence_value(a, "domain_entropy") for a in dga]
    entropies = [e for e in entropies if e > 0]

    by_source: dict[str, int] = {}
    for a in dga:
        by_source[a.source_ip] = by_source.get(a.source_ip, 0) + 1

    return {
        "detection_active": engine_ready(),
        "dga_detections": len(dga),
        "tunnel_detections": len(tunnel),
        "total": len(dga) + len(tunnel),
        "mean_domain_entropy": round(sum(entropies) / len(entropies), 3) if entropies else None,
        "entropy_samples": len(entropies),
        "top_sources": [
            {"source_ip": ip, "detections": n}
            for ip, n in sorted(by_source.items(), key=lambda kv: kv[1], reverse=True)[:10]
        ],
        "samples": [
            {
                "alert_id": a.alert_id,
                "source_ip": a.source_ip,
                "destination_ip": a.destination_ip,
                "domain_entropy": _evidence_value(a, "domain_entropy"),
                "bigram_likelihood": _evidence_value(a, "bigram_likelihood"),
                "confidence": round(float(a.confidence), 4),
                "severity": a.severity,
            }
            for a in dga[:25]
        ],
    }


@router.get("/analytics/tls", summary="TLS detector telemetry")
async def tls_analytics(alert_manager: Any = Depends(get_alert_manager)) -> dict[str, Any]:
    if alert_manager is None:
        raise HTTPException(status_code=503, detail={"error": "alert_store_unavailable"})
    tls = _class_alerts(alert_manager, {"tls_malware"})
    malicious = [a for a in tls if str(a.severity).lower() in ("high", "critical")]
    return {
        "detection_active": engine_ready(),
        # JA3S needs the ServerHello, which a one-way tap cannot observe. The
        # UI renders this as an explicit inactive sensor rather than filling
        # the panel with numbers we cannot actually derive.
        "ja3s_available": False,
        "ja3s_reason": "JA3S requires ServerHello; unavailable on a unidirectional tap",
        "sessions_flagged": len(tls),
        "malware_verdicts": len(malicious),
        "fingerprints": [
            {
                "alert_id": a.alert_id,
                "flow_id": a.flow_id,
                "source_ip": a.source_ip,
                "destination_ip": a.destination_ip,
                "extensions_count": _evidence_value(a, "extensions_count"),
                "ciphers_count": _evidence_value(a, "ciphers_count"),
                "confidence": round(float(a.confidence), 4),
                "severity": a.severity,
            }
            for a in tls[:25]
        ],
    }


# ── PCAP / flow-file upload ───────────────────────────────────────────
# The pre-existing POST /ingest/pcap accepted a server-side `filepath` straight
# from the request body and opened it, which let a caller read any path the
# process could reach. This endpoint takes the bytes instead: the file is
# written to a controlled directory under a generated name, so nothing the
# caller sends is ever used as a path.

_MAX_UPLOAD_BYTES = 100 * 1024 * 1024  # 100 MB
_ALLOWED_SUFFIXES = {".pcap", ".pcapng", ".cap", ".json"}


@router.post("/pcap/upload", summary="Upload a PCAP/JSON flow file and replay it")
async def upload_pcap(
    file: UploadFile = File(...),
    alert_manager: Any = Depends(get_alert_manager),
) -> dict[str, Any]:
    import os
    import uuid
    from pathlib import Path

    from app.api.deps import get_inference_engine, get_alert_broadcaster
    from app.alerts.broadcaster import AlertBroadcaster
    from app.config import settings
    from app.ingest.pipeline import ingest_pcap_file, get_ingest_status

    if alert_manager is None:
        raise HTTPException(status_code=503, detail={"error": "alert_store_unavailable"})
    engine = get_inference_engine()
    if engine is None:
        raise HTTPException(
            status_code=503,
            detail={
                "error": "inference_engine_unavailable",
                "cause": get_engine_error() or "engine not initialised",
            },
        )

    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in _ALLOWED_SUFFIXES:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "unsupported_file_type",
                "received": suffix or "(none)",
                "allowed": sorted(_ALLOWED_SUFFIXES),
            },
        )

    upload_dir = Path(settings.pcap_dir) / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    # Generated name: the client's filename never touches the filesystem path.
    dest = upload_dir / f"upload_{uuid.uuid4().hex}{suffix}"

    written = 0
    try:
        with dest.open("wb") as fh:
            while chunk := await file.read(1024 * 1024):
                written += len(chunk)
                if written > _MAX_UPLOAD_BYTES:
                    fh.close()
                    dest.unlink(missing_ok=True)
                    raise HTTPException(
                        status_code=413,
                        detail={"error": "file_too_large", "max_bytes": _MAX_UPLOAD_BYTES},
                    )
                fh.write(chunk)
    except HTTPException:
        raise
    except Exception as e:
        dest.unlink(missing_ok=True)
        logger.exception("PCAP upload failed")
        raise HTTPException(status_code=500, detail={"error": "upload_failed", "cause": str(e)})

    if written == 0:
        dest.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail={"error": "empty_file"})

    broadcaster = get_alert_broadcaster() or AlertBroadcaster()
    before = len(alert_manager.get_active_alerts())
    try:
        flows = await ingest_pcap_file(
            str(dest), alert_manager, engine, broadcaster, get_metrics(),
            data_source="PCAP_REPLAY",
        )
    except Exception as e:
        logger.exception("PCAP replay failed")
        raise HTTPException(status_code=422, detail={"error": "replay_failed", "cause": str(e)})
    after = len(alert_manager.get_active_alerts())

    return {
        "status": "replayed",
        "original_filename": file.filename,
        "stored_as": dest.name,
        "bytes_received": written,
        "flows_processed": flows,
        "alerts_generated": max(0, after - before),
        "ingest_status": get_ingest_status(),
    }


@router.get("/models", summary="Deployed model metrics from measured artifacts")
async def model_metrics() -> dict[str, Any]:
    """Serve evaluation.json so the UI shows measured metrics, not constants.

    The AI Engine page used to render a hardcoded MODELS array in the frontend
    that still claimed DGA test AUC 1.0 — a figure the team's own audit had
    already identified as a domain-length artifact. The app therefore
    contradicted the submission deck. This endpoint reads the file produced by
    scripts/regenerate_evaluation.py so there is exactly one source of truth.
    """
    import json
    from pathlib import Path

    from app.config import settings

    candidates = [
        Path(settings.artifacts_dir) / "evaluation.json",
        Path(settings.models_dir) / "evaluation.json",
        Path(__file__).resolve().parents[3] / "data" / "models" / "evaluation.json",
    ]
    for path in candidates:
        try:
            data = json.loads(path.read_text())
        except (FileNotFoundError, NotADirectoryError):
            continue
        except json.JSONDecodeError as e:
            raise HTTPException(
                status_code=500,
                detail={"error": "evaluation_json_invalid", "path": str(path), "cause": str(e)},
            )
        data["_source"] = str(path)
        return data

    raise HTTPException(
        status_code=503,
        detail={
            "error": "evaluation_artifacts_missing",
            "message": "No evaluation.json found.",
            "regenerate_with": "python3 scripts/regenerate_evaluation.py",
        },
    )
