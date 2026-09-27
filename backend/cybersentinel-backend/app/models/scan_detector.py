from __future__ import annotations

import time as _time
from typing import Any, Dict, List, Optional

from sklearn.preprocessing import StandardScaler

from app.config import settings
from app.alerts.schema import Evidence
from app.features.scan_features import (
    compute_fan_out_unique_dst_ports,
    compute_fan_out_unique_dst_hosts,
    classify_scan_type,
)


class _SrcState:
    """Per-source fan-out, maintained incrementally.

    Holds the same bounded window of flows the old implementation stored
    (last 4,000 flow keys, oldest evicted first) but keeps reference counts of
    the ports and hosts they contribute, so the distinct counts are read in
    O(1) instead of re-walking every stored flow on every new flow (measured
    ~1,080 us/flow on a realistic stream - the pipeline's worst bottleneck).
    """
    __slots__ = ("flows", "ports", "hosts", "summ", "last_seen")

    def __init__(self):
        self.flows: Dict[str, tuple] = {}     # key -> (dst_ip, ports, summary)
        self.ports: Dict[Any, int] = {}
        self.hosts: Dict[str, int] = {}
        self.summ: Dict[str, int] = {}
        self.last_seen = 0.0

    def _add_contrib(self, key, dst_ip, ports, summary):
        for p in ports:
            self.ports[p] = self.ports.get(p, 0) + 1
        self.hosts[dst_ip] = self.hosts.get(dst_ip, 0) + 1
        if summary:
            self.summ[key] = summary

    def _remove_contrib(self, key, entry):
        dst_ip, ports, summary = entry
        for p in ports:
            c = self.ports[p] - 1
            if c:
                self.ports[p] = c
            else:
                del self.ports[p]
        c = self.hosts[dst_ip] - 1
        if c:
            self.hosts[dst_ip] = c
        else:
            del self.hosts[dst_ip]
        if summary:
            self.summ.pop(key, None)

    def add(self, key, dst_ip, ports, summary, cap):
        old = self.flows.get(key)
        if old is not None:                       # same key: update in place
            self._remove_contrib(key, old)
        entry = (dst_ip, ports, summary)
        self.flows[key] = entry
        self._add_contrib(key, dst_ip, ports, summary)
        if len(self.flows) > cap:
            oldest = next(iter(self.flows))
            self._remove_contrib(oldest, self.flows.pop(oldest))

    def unique_ports(self) -> int:
        return max(len(self.ports), max(self.summ.values()) if self.summ else 0)

    def unique_hosts(self) -> int:
        return len(self.hosts)


def _ports_of(flow_dict: dict) -> tuple:
    ports = set(flow_dict.get("dst_ports", []) or [])
    dp = flow_dict.get("dst_port")
    if dp is not None:
        ports.add(dp)
    return tuple(ports)


def _summary_of(flow_dict: dict) -> int:
    raw = flow_dict.get("raw_features") or {}
    if isinstance(raw, dict) and raw.get("unique_dst_ports"):
        return int(raw["unique_dst_ports"])
    return 0


class ScanDetector:
    FLOW_CAP = 4000

    def __init__(
        self,
        window_seconds: int = 60,
        unique_ports_threshold: int | None = None,
        unique_hosts_threshold: int | None = None,
        idle_ttl_seconds: float = 900.0,
    ):
        self.window_seconds = window_seconds
        self.unique_ports_threshold = unique_ports_threshold if unique_ports_threshold is not None else settings.scan_unique_ports_threshold
        self.unique_hosts_threshold = unique_hosts_threshold if unique_hosts_threshold is not None else settings.scan_unique_hosts_threshold
        self._src: Dict[str, _SrcState] = {}
        # Sources idle this long are forgotten (memory bound under spoofed
        # floods, which create one source per flow). Wall-clock based.
        self.idle_ttl_seconds = idle_ttl_seconds
        self._ops = 0
        self._scaler = StandardScaler()
        self.is_fitted = False

    # Legacy views kept for callers/tests that inspect the stored flows.
    @property
    def _src_flows(self) -> Dict[str, Dict[str, tuple]]:
        return {ip: st.flows for ip, st in self._src.items()}

    def add_flow(self, src_ip: str, flow_key: str, flow_dict: dict):
        st = self._src.get(src_ip)
        if st is None:
            st = self._src[src_ip] = _SrcState()
        st.last_seen = _time.monotonic()
        st.add(flow_key, flow_dict.get("dst_ip", ""), _ports_of(flow_dict), _summary_of(flow_dict), self.FLOW_CAP)
        self._ops += 1
        if self._ops % 50_000 == 0:
            self._evict_idle()
        return st

    def _evict_idle(self):
        cutoff = _time.monotonic() - self.idle_ttl_seconds
        for ip in [ip for ip, st in self._src.items() if st.last_seen < cutoff]:
            del self._src[ip]

    def detect_flow(self, flow: Any) -> Optional[dict]:
        """Fast path for FlowState objects: same values FlowState.to_dict()
        would feed detect(), without building the whole dict per flow."""
        raw = getattr(flow, "raw_features", None) or {}
        dst_ports = getattr(flow, "dst_ports", None) or set()
        view = {
            "key": getattr(flow, "key", None), "src_ip": getattr(flow, "src_ip", ""),
            "dst_ip": getattr(flow, "dst_ip", ""), "dst_port": getattr(flow, "dst_port", None),
            "dst_ports": dst_ports, "raw_features": raw,
            "dst_port_count": max(len(dst_ports), int(raw.get("unique_dst_ports") or 0)),
            "unique_dst_hosts": max(1, int(raw.get("unique_dst_hosts") or 1)),
        }
        return self.detect(view)

    def detect(self, flow: dict, all_flows_from_src: dict | None = None) -> Optional[dict]:
        try:
            src_ip = flow.get("src_ip", "")
            flow_key = str(flow.get("key") or flow.get("flow_id") or id(flow))
            st = self.add_flow(src_ip, flow_key, flow)

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

            if all_flows_from_src is not None:
                # Explicit table supplied by the caller: original computation.
                if all_flows_from_src:
                    unique_dst_ports = max(unique_dst_ports, compute_fan_out_unique_dst_ports(src_ip, all_flows_from_src))
                    unique_dst_hosts = max(unique_dst_hosts, compute_fan_out_unique_dst_hosts(src_ip, all_flows_from_src))
            else:
                unique_dst_ports = max(unique_dst_ports, st.unique_ports())
                unique_dst_hosts = max(unique_dst_hosts, st.unique_hosts())

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
