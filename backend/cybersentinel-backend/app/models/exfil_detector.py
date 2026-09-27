from __future__ import annotations

import numpy as np
from typing import Dict, List, Any, Optional

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from app.config import settings
from app.alerts.schema import Evidence
from app.features.exfil_features import compute_one_sided_exfil_features


class ExfiltrationDetector:
    """Data exfiltration detector — PS item (f).

    Reads outbound volume and packet-size profile: both observable from the
    outbound direction alone. This used to compute an "outbound_inbound_ratio"
    and "byte_skew" from inbound_bytes, which is never populated on a
    unidirectional tap and defaulted to 0 — making the displayed ratio
    numerically equal to raw outbound bytes and the skew always exactly 1.0.
    Functionally the detector still worked (the effective rule reduced to
    "large outbound volume"), but the evidence it showed analysts claimed
    bidirectional visibility the system does not have, which is exactly the
    kind of number this project's own audit exists to catch.
    """

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
            X = [[fh.get("outbound_bytes_abs", 0), fh.get("bytes_per_packet", 0.0),
                  fh.get("throughput_bytes_sec", 0.0)] for fh in self._flow_history]
            X = np.array(X, dtype=float)
            X_scaled = self.scaler.fit_transform(X)
            self.iforest.fit(X_scaled)
            self.is_fitted = True
        except Exception:
            pass

    @staticmethod
    def _extract(flow: Any) -> dict:
        outbound_bytes = getattr(flow, "bytes_transferred", 0) or 0
        packet_count = getattr(flow, "packet_count", 0) or 0
        dur = flow.duration_seconds() if hasattr(flow, "duration_seconds") else 1.0
        return compute_one_sided_exfil_features(outbound_bytes, packet_count, max(dur, 1.0))

    def _severity(self, total_bytes: float) -> str:
        if total_bytes > 100 * 1024 * 1024:
            return "critical"
        if total_bytes > 10 * 1024 * 1024:
            return "high"
        if total_bytes > 1 * 1024 * 1024:
            return "medium"
        return "low"

    def _alert(self, feats: dict, rule_based: bool, ml_based: bool, anomaly_score: Optional[float]) -> Optional[dict]:
        if not (rule_based or ml_based):
            return None
        if rule_based and ml_based:
            confidence = 0.9
        elif rule_based:
            confidence = 0.82
        else:
            confidence = min(1.0, abs(anomaly_score) * 2) if anomaly_score is not None else 0.0
        out_bytes = feats["outbound_bytes_abs"]
        evidence = [
            Evidence(feature_name="outbound_bytes_abs", value=round(out_bytes, 0), contribution=0.45,
                     description=f"Outbound volume observed: {out_bytes / 1024:.0f} KB (no inbound side to compare on this link)"),
            Evidence(feature_name="bytes_per_packet", value=round(feats["bytes_per_packet"], 1), contribution=0.35,
                     description=f"Average packet size {feats['bytes_per_packet']:.0f} B — large packets suggest bulk transfer"),
            Evidence(feature_name="throughput_bytes_sec", value=round(feats["throughput_bytes_sec"], 2), contribution=0.20,
                     description=f"Sustained throughput: {feats['throughput_bytes_sec']:.0f} B/s"),
        ]
        return {
            "threat_class": "exfiltration",
            "severity": self._severity(out_bytes),
            "confidence": round(confidence, 4),
            "evidence": evidence,
            "model_version": "one_sided_exfil_v2",
        }

    def detect(self, flow: Any) -> Optional[dict]:
        try:
            feats = self._extract(flow)
            rule_based = bool(feats["exfil_likely"])
            ml_based = False
            score = None
            if self.is_fitted:
                try:
                    vec = np.array([[feats["outbound_bytes_abs"], feats["bytes_per_packet"], feats["throughput_bytes_sec"]]], dtype=float)
                    scaled = self.scaler.transform(vec)
                    score = float(self.iforest.decision_function(scaled)[0])
                    ml_based = score < 0
                except Exception:
                    pass
            return self._alert(feats, rule_based, ml_based, score)
        except Exception:
            return None

    def detect_batch(self, flows: List[Any]) -> List[Optional[dict]]:
        results: List[Optional[dict]] = [None] * len(flows)
        model_indices: List[int] = []
        model_rows: List[List[float]] = []
        model_feats: List[dict] = []

        for i, flow in enumerate(flows):
            try:
                feats = self._extract(flow)
                rule_based = bool(feats["exfil_likely"])
                if self.is_fitted:
                    model_indices.append(i)
                    model_rows.append([feats["outbound_bytes_abs"], feats["bytes_per_packet"], feats["throughput_bytes_sec"]])
                    model_feats.append((feats, rule_based))
                elif rule_based:
                    results[i] = self._alert(feats, True, False, None)
            except Exception:
                continue

        if model_rows:
            scores = None
            try:
                X = np.array(model_rows, dtype=float)
                scaled = self.scaler.transform(X)
                scores = self.iforest.decision_function(scaled)
            except Exception:
                scores = None
            for j, i in enumerate(model_indices):
                feats, rule_based = model_feats[j]
                if scores is not None:
                    score = float(scores[j])
                    ml_based = score < 0
                else:
                    score, ml_based = None, False
                results[i] = self._alert(feats, rule_based, ml_based, score)
        return results
