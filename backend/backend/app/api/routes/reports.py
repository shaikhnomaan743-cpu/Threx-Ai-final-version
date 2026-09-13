from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse, StreamingResponse, Response
from fastapi.encoders import jsonable_encoder
from typing import Any, Optional, Literal
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import csv
import io
import json
import logging

from app.api.deps import get_alert_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/reports", tags=["reports"])


class ReportConfig(BaseModel):
    """Report generation request with filters."""
    format: Literal["json", "csv"] = Field(default="json", description="Output format: json or csv")
    threat_class: Optional[str] = Field(default=None, description="Filter by threat class")
    severity: Optional[str] = Field(default=None, description="Filter by severity")
    limit: int = Field(default=100, ge=1, le=10000, description="Max number of alerts")
    include_evidence: bool = Field(default=True, description="Include evidence details")
    include_raw_features: bool = Field(default=False, description="Include raw_features")
    # Back-compat aliases
    report_type: Optional[str] = Field(default=None, description="Legacy: report_type alias")
    type: Optional[str] = Field(default=None, description="Legacy: type alias")


def _filter_alerts(alerts: list, cfg: ReportConfig) -> list:
    filtered = alerts
    if cfg.threat_class:
        filtered = [a for a in filtered if getattr(a, "threat_class", None) == cfg.threat_class]
    elif cfg.report_type and cfg.report_type != "threat_summary":
        # treat report_type as threat_class filter if valid
        valid = {"ddos", "c2_beacon", "dga", "dns_tunnel", "tls_malware", "port_scan", "exfiltration"}
        if cfg.report_type in valid:
            filtered = [a for a in filtered if getattr(a, "threat_class", None) == cfg.report_type]
    if cfg.severity:
        filtered = [a for a in filtered if getattr(a, "severity", None) == cfg.severity]
    # sort by timestamp desc
    try:
        filtered.sort(key=lambda a: getattr(a, "timestamp", datetime.now(timezone.utc)), reverse=True)
    except Exception:
        pass
    return filtered[: cfg.limit]


def _alert_to_row(alert: Any, cfg: ReportConfig) -> dict:
    """Convert alert to flat dict for CSV/JSON."""
    try:
        # Pydantic model_dump if available
        if hasattr(alert, "model_dump"):
            d = alert.model_dump()
        elif hasattr(alert, "dict"):
            d = alert.dict()
        else:
            d = dict(alert)
    except Exception:
        d = {
            "alert_id": getattr(alert, "alert_id", ""),
            "timestamp": str(getattr(alert, "timestamp", "")),
            "threat_class": getattr(alert, "threat_class", ""),
            "severity": getattr(alert, "severity", ""),
            "confidence": getattr(alert, "confidence", 0),
            "source_ip": getattr(alert, "source_ip", ""),
            "destination_ip": getattr(alert, "destination_ip", ""),
            "source_port": getattr(alert, "source_port", ""),
            "destination_port": getattr(alert, "destination_port", ""),
            "protocol": getattr(alert, "protocol", ""),
            "bytes_transferred": getattr(alert, "bytes_transferred", 0),
            "packet_count": getattr(alert, "packet_count", 0),
            "duration_seconds": getattr(alert, "duration_seconds", 0),
        }
    if not cfg.include_evidence and "evidence" in d:
        d.pop("evidence", None)
    if not cfg.include_raw_features and "raw_features" in d:
        d.pop("raw_features", None)
    # flatten evidence for CSV-friendly
    return d


@router.post("/generate", summary="Generate threat report")
async def generate_report(
    cfg: ReportConfig | None = None,
    report_type: str | None = Query(default=None, description="Legacy query param"),
    alert_manager: Any = Depends(get_alert_manager),
):
    """Generate report from alert_manager with filters.

    Supports both JSON body (ReportConfig) and legacy query param.
    Returns:
      - JSON blob when format=json (default): includes report_id, generated_at, summary, data
      - CSV blob when format=csv: StreamingResponse text/csv
    """
    if not alert_manager:
        return JSONResponse(status_code=503, content={"report_id": "error", "status": "no_alert_manager", "detail": "Alert manager not initialized yet - try again"})

    # Handle case where caller sent raw JSON without model validation (fallback)
    if cfg is None:
        cfg = ReportConfig(format="json")  # type: ignore
        if report_type:
            cfg.report_type = report_type

    # Back-compat: query param overrides body if provided
    if report_type and not cfg.threat_class and not cfg.report_type:
        cfg.report_type = report_type
        cfg.threat_class = report_type if report_type in {"ddos", "c2_beacon", "dga", "dns_tunnel", "tls_malware", "port_scan", "exfiltration"} else None

    # Normalize format legacy aliases
    fmt = (cfg.format or "json").lower()
    if cfg.type and cfg.type.lower() in ("json", "csv"):
        fmt = cfg.type.lower()
    cfg.format = fmt  # type: ignore

    alerts = alert_manager.get_active_alerts()
    filtered = _filter_alerts(alerts, cfg)

    report_id = f"rpt-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    generated_at = datetime.now(timezone.utc).isoformat()

    # Build summary counts
    severity_counts = {
        "critical": len([a for a in filtered if getattr(a, "severity", None) == "critical"]),
        "high": len([a for a in filtered if getattr(a, "severity", None) == "high"]),
        "medium": len([a for a in filtered if getattr(a, "severity", None) == "medium"]),
        "low": len([a for a in filtered if getattr(a, "severity", None) == "low"]),
    }

    if fmt == "csv":
        # Generate CSV blob
        output = io.StringIO()
        fieldnames = ["alert_id", "timestamp", "threat_class", "severity", "confidence", "source_ip", "source_port", "destination_ip", "destination_port", "protocol", "bytes_transferred", "packet_count", "duration_seconds"]
        if cfg.include_evidence:
            fieldnames.append("evidence")
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for alert in filtered:
            row = _alert_to_row(alert, cfg)
            # Serialize evidence list to JSON string for CSV
            if "evidence" in row and isinstance(row["evidence"], list):
                row["evidence"] = json.dumps([e.model_dump() if hasattr(e, "model_dump") else dict(e) if isinstance(e, dict) else str(e) for e in row["evidence"]])
            writer.writerow({k: row.get(k, "") for k in fieldnames})
        csv_content = output.getvalue()
        return StreamingResponse(
            io.BytesIO(csv_content.encode("utf-8")),
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename={report_id}.csv",
                "X-Report-Id": report_id,
                "X-Total-Threats": str(len(filtered)),
            },
        )

    # Default JSON
    data_rows = [_alert_to_row(a, cfg) for a in filtered]
    # Also handle legacy expectations: total_threats, critical/high etc
    response = {
        "report_id": report_id,
        "status": "generated",
        "type": cfg.threat_class or cfg.report_type or report_type or "threat_summary",
        "format": fmt,
        "total_threats": len(filtered),
        "generated_at": generated_at,
        "filters": {
            "threat_class": cfg.threat_class,
            "severity": cfg.severity,
            "limit": cfg.limit,
            "include_evidence": cfg.include_evidence,
        },
        "summary": {
            **severity_counts,
            "total": len(filtered),
        },
        # Back-compat flat counts
        "critical": severity_counts["critical"],
        "high": severity_counts["high"],
        "medium": severity_counts["medium"],
        "low": severity_counts["low"],
        "data": data_rows,
        # Blob helper for frontend download
        "blob_mime": "application/json",
    }
    return JSONResponse(content=jsonable_encoder(response))


@router.get("/generate", summary="Generate threat report (GET for testing)")
async def generate_report_get(
    format: str = Query(default="json", description="json or csv"),
    threat_class: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=10000),
    alert_manager: Any = Depends(get_alert_manager),
):
    """GET alias for convenience/testing. Delegates to POST logic."""
    cfg = ReportConfig(format=format.lower(), threat_class=threat_class, severity=severity, limit=limit)  # type: ignore
    return await generate_report(cfg=cfg, alert_manager=alert_manager)  # type: ignore
