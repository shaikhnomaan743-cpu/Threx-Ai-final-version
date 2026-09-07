from __future__ import annotations

import numpy as np
from typing import Dict, List, Any, Optional

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from app.config import settings
from app.alerts.schema import Evidence


class DDOSDetector:
    def __init__(self, contamination: float = 0.05):
        self.contamination = contamination
        self.iforest = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100,
        )
        self.scaler = StandardScaler()
        self.is_fitted = False
        self._packets: List[Any] = []

    def update(self, features: dict, pkt_info: Any):
        self._packets.append(pkt_info)

    def detect(self, flow: Any) -> Optional[dict]:
        try:
            pkt_rate = flow.packet_count / max(flow.duration_seconds(), 1.0) if hasattr(flow, "packet_count") else 0
            byte_rate = flow.bytes_transferred / max(flow.duration_seconds(), 1.0) if hasattr(flow, "bytes_transferred") else 0
            syn_ratio = 0.0
            amp_ratio = 0.0
            if hasattr(flow, "raw_features") and isinstance(flow.raw_features, dict):
                syn_ratio = flow.raw_features.get("syn_to_ack_ratio", 0.0)
                amp_ratio = flow.raw_features.get("amplification_ratio", 0.0)

            if syn_ratio > settings.ddos_syn_ratio:
                return {
                    "threat_class": "ddos",
                    "severity": "high",
                    "confidence": min(1.0, syn_ratio / 50.0),
                    "evidence": [
                        Evidence(
                            feature_name="syn_to_ack_ratio",
                            value=round(syn_ratio, 2),
                            contribution=0.7,
                            description=f"SYN flood detected: SYN/ACK ratio = {syn_ratio:.1f}:1 (threshold: {settings.ddos_syn_ratio}:1)"
                        ),
                        Evidence(
                            feature_name="packet_rate",
                            value=round(pkt_rate, 2),
                            contribution=0.3,
                            description=f"High packet rate: {pkt_rate:.1f} pps"
                        )
                    ],
                    "model_version": "rule_isolation_forest_v1",
                }
            if amp_ratio > settings.ddos_udp_amp_ratio:
                return {
                    "threat_class": "ddos",
                    "severity": "medium",
                    "confidence": min(1.0, amp_ratio / 50.0),
                    "evidence": [
                        Evidence(
                            feature_name="amplification_ratio",
                            value=round(amp_ratio, 2),
                            contribution=0.8,
                            description=f"UDP amplification detected: response/request = {amp_ratio:.1f}:1 (threshold: {settings.ddos_udp_amp_ratio}:1)"
                        )
                    ],
                    "model_version": "rule_amplification_v1",
                }
            if self.is_fitted and pkt_rate >= 80:
                try:
                    features_vector = np.array([[pkt_rate, byte_rate]]).astype(float)
                    scaled = self.scaler.transform(features_vector)
                    anomaly_score = float(self.iforest.decision_function(scaled)[0])
                    is_anomaly = anomaly_score < 0
                    if is_anomaly:
                        confidence = min(1.0, abs(anomaly_score) * 2)
                        return {
                            "threat_class": "ddos",
                            "severity": "high" if confidence > 0.6 else "medium",
                            "confidence": confidence,
                            "evidence": [
                                Evidence(feature_name="packet_rate", value=round(pkt_rate,2), contribution=0.4, description=f"Anomalous packet rate: {pkt_rate:.1f} pps"),
                                Evidence(feature_name="byte_rate", value=round(byte_rate,2), contribution=0.4, description=f"Anomalous byte rate: {byte_rate:.1f} B/s"),
                                Evidence(feature_name="isolation_forest_score", value=round(anomaly_score,4), contribution=0.2, description="IsolationForest anomaly score (negative = attack)")
                            ],
                            "model_version": "isolation_forest_v1",
                        }
                except Exception:
                    pass
        except Exception:
            pass
        return None

_detector_instances: Dict[str, DDOSDetector] = {}

def get_ddos_detector(protocol: str = "tcp") -> DDOSDetector:
    if protocol not in _detector_instances:
        _detector_instances[protocol] = DDOSDetector(contamination=settings.ddos_contamination)
    return _detector_instances[protocol]
