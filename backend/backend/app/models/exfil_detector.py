from __future__ import annotations

import numpy as np
from typing import Dict, List, Any, Optional

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from app.config import settings
from app.alerts.schema import Evidence
from app.features.exfil_features import compute_outbound_inbound_ratio, compute_session_duration_stats, compute_byte_skew


class ExfiltrationDetector:
    def __init__(self, contamination: float = 0.05):
        self.contamination = contamination
        self.iforest = IsolationForest(contamination=contamination, random_state=42, n_estimators=100)
        self.scaler = StandardScaler()
        self.is_fitted = False
        self._flow_history: List[dict] = []

    def update(self, flow_features: dict):
        self._flow_history.append(flow_features)
        if len(self._flow_history) > 10000:
            self._flow_history = self._flow_history[-5000:]
        if len(self._flow_history) >= 100 and not self.is_fitted:
            self._lazy_fit()

    def _lazy_fit(self):
        try:
            if len(self._flow_history) < 20:
                return
            X = []
            for fh in self._flow_history:
                vec = [fh.get("outbound_bytes",0), fh.get("inbound_bytes",0), fh.get("ratio",0.0), fh.get("duration_seconds",0.0), fh.get("byte_skew",0.0), fh.get("throughput_bytes_sec",0.0)]
                X.append(vec)
            X = np.array(X, dtype=float)
            X_scaled = self.scaler.fit_transform(X)
            self.iforest.fit(X_scaled)
            self.is_fitted = True
        except Exception:
            pass

    def detect(self, flow: Any) -> Optional[dict]:
        try:
            outbound_bytes = flow.raw_features.get("outbound_bytes", 0) if hasattr(flow, 'raw_features') else 0
            inbound_bytes = flow.raw_features.get("inbound_bytes", 0) if hasattr(flow, 'raw_features') else 0
            # fallback to bytes_transferred if directional not set
            if outbound_bytes == 0 and inbound_bytes == 0 and hasattr(flow, "bytes_transferred"):
                outbound_bytes = flow.bytes_transferred
            ratio_info = compute_outbound_inbound_ratio(outbound_bytes, inbound_bytes)
            duration_info = compute_session_duration_stats(flow)
            skew = compute_byte_skew(outbound_bytes, inbound_bytes)
            total_bytes = outbound_bytes + inbound_bytes
            rule_based = (ratio_info["exfil_likely"] or (duration_info["is_long_duration"] and duration_info["throughput_bytes_sec"] < 10_000 and total_bytes > 1_000_000))
            ml_based = False
            confidence = 0.0
            if self.is_fitted:
                try:
                    feature_vector = np.array([[outbound_bytes, inbound_bytes, ratio_info["ratio"], duration_info["duration_seconds"], skew, duration_info["throughput_bytes_sec"]]], dtype=float)
                    if feature_vector.shape[1] > 0:
                        feature_vector_scaled = self.scaler.transform(feature_vector)
                        anomaly_score = float(self.iforest.decision_function(feature_vector_scaled)[0])
                        ml_based = anomaly_score < 0
                        confidence = min(1.0, abs(anomaly_score) * 2)
                except Exception:
                    pass
            if rule_based or ml_based:
                if rule_based and ml_based:
                    final_confidence = min(1.0, confidence * 1.5 if confidence>0 else 0.85)
                elif rule_based:
                    final_confidence = 0.82
                else:
                    final_confidence = min(1.0, confidence)
                if total_bytes > 100 * 1024 * 1024:
                    severity = "critical"
                elif total_bytes > 10 * 1024 * 1024:
                    severity = "high"
                elif total_bytes > 1 * 1024 * 1024:
                    severity = "medium"
                else:
                    severity = "low"
                return {
                    "threat_class": "exfiltration",
                    "severity": severity,
                    "confidence": round(final_confidence, 4),
                    "evidence": [
                        Evidence(feature_name="outbound_inbound_ratio", value=round(ratio_info["ratio"],2), contribution=0.35, description=f"Outbound:inbound byte ratio: {ratio_info['ratio']:.1f}:1"),
                        Evidence(feature_name="total_bytes_transferred", value=total_bytes, contribution=0.25, description=f"Total bytes transferred: {total_bytes // 1024}KB"),
                        Evidence(feature_name="byte_skew", value=round(skew,3), contribution=0.2, description=f"Byte direction skew: {skew:.3f}"),
                        Evidence(feature_name="duration_seconds", value=round(duration_info["duration_seconds"],2), contribution=0.15, description=f"Flow duration: {duration_info['duration_seconds']:.1f}s"),
                        Evidence(feature_name="throughput_bytes_sec", value=round(duration_info["throughput_bytes_sec"],2), contribution=0.05, description=f"Throughput: {duration_info['throughput_bytes_sec']:.0f} B/s")
                    ],
                    "model_version": "isolation_forest_exfil_v1",
                }
        except Exception:
            pass
        return None
