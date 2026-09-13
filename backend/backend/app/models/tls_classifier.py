from __future__ import annotations

import numpy as np
from typing import Dict, List, Any, Optional

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from app.alerts.schema import Evidence


class TLSMalwareClassifier:
    def __init__(self, n_estimators: int = 100, random_state: int = 42):
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.model = RandomForestClassifier(n_estimators=n_estimators, random_state=random_state, max_depth=10, min_samples_leaf=5, class_weight="balanced")
        self.scaler = StandardScaler()
        self.is_fitted = False
        self._tls_metadata: List[dict] = []

    def add_tls_metadata(self, metadata: dict):
        self._tls_metadata.append(metadata)

    def fit(self, labeled_samples: List[dict]):
        if not labeled_samples:
            return
        X = []
        y = []
        for sample in labeled_samples:
            features = [sample.get("ciphers_count",0), sample.get("extensions_count",0), sample.get("curves_count",0), sample.get("point_formats_count",0)] + self._extract_size_seq_features(sample.get("packet_size_sequence",[]))
            X.append(features)
            y.append(sample.get("label",0))
        if len(X) < 10:
            return
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled, y)
        self.is_fitted = True

    def _extract_size_seq_features(self, seq: List[float]) -> List[float]:
        if not seq:
            return [0.0, 0.0, 0.0, 0.0, 0.0]
        arr = np.array(seq, dtype=float)
        return [float(np.mean(arr)), float(np.median(arr)), float(np.std(arr)) if len(arr)>1 else 0.0, float(np.min(arr)), float(np.max(arr))]

    def predict(self, flow: Any) -> Optional[dict]:
        if not self.is_fitted:
            return None
        raw = flow.raw_features if hasattr(flow, 'raw_features') else {}
        if not isinstance(raw, dict):
            raw = {}
        ja3 = getattr(flow, "ja3", "") or raw.get("ja3") or ""
        dport = getattr(flow, "dst_port", None)
        has_tls_meta = bool(ja3) or any(k in raw for k in ("ciphers_count", "extensions_count", "curves_count"))
        if not has_tls_meta and dport not in (443, 853, 8443):
            return None
        # Zeroed ClientHello features on non-TLS flows match the malware
        # training prior — require at least a JA3 string or TLS port + features.
        if not has_tls_meta:
            return None
        ciphers_count = raw.get("ciphers_count", 0)
        extensions_count = raw.get("extensions_count", 0)
        curves_count = raw.get("curves_count", 0)
        point_formats_count = raw.get("point_formats_count", 0)
        packet_size_seq = raw.get("packet_size_sequence", [])
        size_features = self._extract_size_seq_features(packet_size_seq)
        features = [ciphers_count, extensions_count, curves_count, point_formats_count] + size_features
        try:
            features_scaled = self.scaler.transform([features])[0]
            prediction = int(self.model.predict([features_scaled])[0])
            probability = float(self.model.predict_proba([features_scaled])[0][prediction])
            feature_names = ["ciphers_count","extensions_count","curves_count","point_formats_count","mean_size","median_size","std_size","min_size","max_size"]
            importances = dict(zip(feature_names, self.model.feature_importances_))
            top_features = sorted(importances.items(), key=lambda x: x[1], reverse=True)[:5]
            evidence_list = []
            for feat_name, imp in top_features:
                idx = list(importances.keys()).index(feat_name)
                evidence_list.append(Evidence(feature_name=feat_name, value=round(features[idx],2), contribution=round(float(imp),4), description=f"{feat_name}: {features[idx]:.2f} (importance: {imp:.3f})"))
            confidence = probability if prediction==1 else 1-probability
            if prediction == 1:
                return {"threat_class":"tls_malware","severity":"high" if confidence>0.7 else "medium","confidence":confidence,"evidence":evidence_list,"model_version":"random_forest_ja3_v1"}
        except Exception:
            pass
        return None

_tls_classifier_instance: TLSMalwareClassifier | None = None

def get_tls_malware_classifier() -> TLSMalwareClassifier:
    global _tls_classifier_instance
    if _tls_classifier_instance is None:
        _tls_classifier_instance = TLSMalwareClassifier()
    return _tls_classifier_instance

def get_tls_classifier():
    return get_tls_malware_classifier()
