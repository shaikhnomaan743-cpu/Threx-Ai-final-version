from __future__ import annotations

from typing import Any, Dict, List, Optional

from sklearn.preprocessing import StandardScaler

from app.config import settings
from app.alerts.schema import Evidence
from app.features.scan_features import (
    compute_fan_out_unique_dst_ports,
    compute_fan_out_unique_dst_hosts,
    classify_scan_type,
)


class ScanDetector:
    def __init__(
        self,
        window_seconds: int = 60,
        unique_ports_threshold: int | None = None,
        unique_hosts_threshold: int | None = None,
    ):
        self.window_seconds = window_seconds
        self.unique_ports_threshold = unique_ports_threshold if unique_ports_threshold is not None else settings.scan_unique_ports_threshold
        self.unique_hosts_threshold = unique_hosts_threshold if unique_hosts_threshold is not None else settings.scan_unique_hosts_threshold
        self._src_flows: Dict[str, Dict[str, dict]] = {}
        self._src_timestamps: Dict[str, List[float]] = {}
        self._scaler = StandardScaler()
        self.is_fitted = False

    def add_flow(self, src_ip: str, flow_key: str, flow_dict: dict):
        if src_ip not in self._src_flows:
            self._src_flows[src_ip] = {}
            self._src_timestamps[src_ip] = []
        self._src_flows[src_ip][flow_key] = flow_dict
        self._src_timestamps[src_ip].append(__import__("time").time())
        # Bound memory for streaming
        if len(self._src_flows[src_ip]) > 4000:
            oldest = next(iter(self._src_flows[src_ip]))
            self._src_flows[src_ip].pop(oldest, None)

    def detect(self, flow: dict, all_flows_from_src: dict | None = None) -> Optional[dict]:
        try:
            src_ip = flow.get("src_ip", "")
            flow_key = str(flow.get("key") or flow.get("flow_id") or id(flow))
            self.add_flow(src_ip, flow_key, flow)

            if all_flows_from_src is None:
                all_flows_from_src = self._src_flows.get(src_ip, {})

            raw = flow.get("raw_features") or {}
            if not isinstance(raw, dict):
                raw = {}

            unique_dst_ports = int(flow.get("dst_port_count") or 0)
            unique_dst_hosts = int(flow.get("unique_dst_hosts") or 0)
            dst_ports_list = flow.get("dst_ports") or []
            if isinstance(dst_ports_list, (list, set, tuple)):
                unique_dst_ports = max(unique_dst_ports, len(set(dst_ports_list)))
            unique_dst_ports = max(unique_dst_ports, int(raw.get("unique_dst_ports") or 0))
            unique_dst_hosts = max(unique_dst_hosts, int(raw.get("unique_dst_hosts") or 0))

            if all_flows_from_src:
                unique_dst_ports = max(unique_dst_ports, compute_fan_out_unique_dst_ports(src_ip, all_flows_from_src))
                unique_dst_hosts = max(unique_dst_hosts, compute_fan_out_unique_dst_hosts(src_ip, all_flows_from_src))

            scan_type = classify_scan_type(unique_dst_ports, unique_dst_hosts)
            is_scan = (
                unique_dst_ports > self.unique_ports_threshold
                or unique_dst_hosts > self.unique_hosts_threshold
            )
            if is_scan:
                if unique_dst_ports > 50 or unique_dst_hosts > 30:
                    severity = "high"
                elif unique_dst_ports > 20 or unique_dst_hosts > 15:
                    severity = "medium"
                else:
                    severity = "low"
                port_excess = unique_dst_ports / max(self.unique_ports_threshold, 1)
                host_excess = unique_dst_hosts / max(self.unique_hosts_threshold, 1)
                confidence = min(1.0, (port_excess + host_excess) / 4.0)
                return {
                    "threat_class": "port_scan",
                    "severity": severity,
                    "confidence": round(confidence, 4),
                    "evidence": [
                        Evidence(feature_name="unique_dst_ports", value=unique_dst_ports, contribution=0.4, description=f"Unique destination ports: {unique_dst_ports} (threshold: {self.unique_ports_threshold})"),
                        Evidence(feature_name="unique_dst_hosts", value=unique_dst_hosts, contribution=0.4, description=f"Unique destination hosts: {unique_dst_hosts} (threshold: {self.unique_hosts_threshold})"),
                        Evidence(feature_name="scan_type", value=1.0 if scan_type == "horizontal" else 0.5, contribution=0.2, description=f"Scan type: {scan_type}"),
                    ],
                    "model_version": "statistical_scan_detector_v1",
                }
        except Exception:
            pass
        return None


_scan_detector_instance: ScanDetector | None = None

def get_scan_detector() -> ScanDetector:
    global _scan_detector_instance
    if _scan_detector_instance is None:
        _scan_detector_instance = ScanDetector()
    return _scan_detector_instance
