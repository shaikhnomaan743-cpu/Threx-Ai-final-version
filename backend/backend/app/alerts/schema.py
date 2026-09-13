from datetime import datetime, timezone
from typing import List, Literal
from pydantic import BaseModel, Field, validator


class Evidence(BaseModel):
    feature_name: str = Field(..., description="Name of the feature that drove detection")
    value: float = Field(..., description="Measured value of the feature")
    contribution: float = Field(
        ..., ge=0.0, le=1.0, description="How much this feature drove the detection (0.0-1.0)"
    )
    description: str = Field(..., description="Human-readable description")


class Alert(BaseModel):
    alert_id: str = Field(..., description="UUID string")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), description="ISO 8601 UTC timestamp"
    )
    flow_id: str = Field(..., description="5-tuple hash identifying the flow")
    threat_class: Literal[
        "ddos", "c2_beacon", "dga", "dns_tunnel",
        "tls_malware", "port_scan", "exfiltration"
    ] = Field(..., description="Threat category")
    severity: Literal["low", "medium", "high", "critical"] = Field(..., description="Severity level")
    confidence: float = Field(
        ge=0.0, le=1.0, description="Overall detection confidence (0.0-1.0)"
    )
    source_ip: str = Field(..., description="Source IP address")
    source_port: int | None = Field(default=None, description="Source port, None if unknown")
    destination_ip: str = Field(..., description="Destination IP address")
    destination_port: int | None = Field(
        default=None, description="Destination port, None if unknown"
    )
    protocol: str = Field(..., description="Network protocol (tcp, udp, icmp)")
    bytes_transferred: int = Field(
        ge=0, description="Total bytes transferred in the flow"
    )
    packet_count: int = Field(
        ge=0, description="Total packet count in the flow"
    )
    duration_seconds: float = Field(
        ge=0, description="Flow duration in seconds"
    )
    evidence: List[Evidence] = Field(
        default_factory=list, description="3-6 supporting features (max 6)"
    )
    model_version: str = Field(
        ..., description="Which model produced this detection"
    )
    raw_features: dict = Field(
        default_factory=dict, description="Full feature vector for forensics"
    )

    @validator("evidence", pre=True)
    def limit_evidence_max(cls, v):
        if isinstance(v, list) and len(v) > 6:
            raise ValueError("Evidence list must have at most 6 items")
        return v

    @validator("protocol")
    def protocol_must_be_valid(cls, v):
        if v not in ("tcp", "udp", "icmp"):
            raise ValueError("Protocol must be one of: tcp, udp, icmp")
        return v