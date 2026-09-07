from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Optional

from app.config import settings
from app.alerts.schema import Evidence
from app.features.beacon_features import (
    compute_inter_arrival_times,
    compute_coefficient_of_variation,
    compute_fft_periodicity,
    compute_jitter,
)


class BeaconDetector:
    """C2 beaconing via intra-flow packet timing AND cross-flow periodicity.

    Problem statement (b): periodicity / inter-arrival on flows repeating at
    regular intervals toward a small set of destinations. That requires
    incremental state across successive flows, not a single-flow snapshot.
    """

    def __init__(self, min_observations: int | None = None):
        self.min_observations = min_observations if min_observations is not None else settings.beacon_min_observations
        self._flow_timestamps: Dict[str, List[float]] = defaultdict(list)
        self._pair_starts: Dict[str, List[float]] = defaultdict(list)
        self._dst_starts: Dict[str, List[float]] = defaultdict(list)
        self.scaler = None

    def update_flow(self, flow_key: str, timestamp: float):
        self._flow_timestamps[flow_key].append(timestamp)

    def _record_cross_flow(self, flow: Any) -> None:
        src = getattr(flow, "src_ip", "") or ""
        dst = getattr(flow, "dst_ip", "") or ""
        dport = getattr(flow, "dst_port", None)
        start = getattr(flow, "start_time", None)
        if start is None or start == float("inf"):
            ts = getattr(flow, "timestamps", []) or []
            start = ts[0] if ts else None
        if start is None:
            return
        start = float(start)
        pair_key = f"{src}|{dst}|{dport}"
        dst_key = f"{dst}|{dport}"
        self._pair_starts[pair_key].append(start)
        self._pair_starts[pair_key] = sorted(self._pair_starts[pair_key])[-64:]

        pkt_count = int(getattr(flow, "packet_count", 0) or 0)
        bytes_xfer = int(getattr(flow, "bytes_transferred", 0) or 0)
        # Sparse sessions (classic beacon) — exclude bulk TLS/exfil to same dest
        if pkt_count <= 40 and bytes_xfer < 25_000:
            self._dst_starts[dst_key].append(start)
            self._dst_starts[dst_key] = sorted(self._dst_starts[dst_key])[-128:]

    def _beacon_from_series(self, timestamps: List[float], min_obs: int) -> Optional[dict]:
        if len(timestamps) < min_obs:
            return None
        iats = compute_inter_arrival_times(sorted(timestamps))
        if len(iats) < max(2, min_obs - 1):
            return None
        cv = compute_coefficient_of_variation(iats)
        mean_iat = float(sum(iats) / len(iats)) if iats else 0.0
        sample_rate = 1.0 / max(mean_iat, 1e-6)
        fft_result = compute_fft_periodicity(sorted(timestamps), sample_rate=sample_rate)
        periodicity_score = float(fft_result["periodicity_score"])
        dominant_period = float(fft_result["dominant_period"] or mean_iat)
        timing_consistency = 1.0 - min(cv, 1.0)
        jitter = compute_jitter(sorted(timestamps))

        # Perfectly regular series put FFT energy in DC — CV is the reliable signal.
        is_periodic = (cv < 0.15 and mean_iat >= 0.4) or (cv < 0.25 and periodicity_score > 0.2)
        if not is_periodic:
            return None

        confidence = round(min(1.0, (timing_consistency * 0.6) + min(periodicity_score, 1.0) * 0.4), 4)
        if confidence < 0.35:
            confidence = round(min(1.0, timing_consistency * 0.85), 4)
        severity = "high" if confidence > 0.5 else "medium"
        return {
            "threat_class": "c2_beacon",
            "severity": severity,
            "confidence": confidence,
            "evidence": [
                Evidence(
                    feature_name="periodicity_score",
                    value=round(periodicity_score, 4),
                    contribution=0.35,
                    description=f"Beacon periodicity score: {periodicity_score:.3f} (dominant period: {dominant_period:.1f}s)",
                ),
                Evidence(
                    feature_name="inter_arrival_cv",
                    value=round(cv, 4),
                    contribution=0.35,
                    description=f"Inter-arrival CV: {cv:.3f} (periodic if < 0.15)",
                ),
                Evidence(
                    feature_name="dominant_period",
                    value=round(dominant_period, 2),
                    contribution=0.2,
                    description=f"Dominant beacon interval: {dominant_period:.1f}s",
                ),
                Evidence(
                    feature_name="jitter",
                    value=round(jitter, 3),
                    contribution=0.1,
                    description=f"Timing jitter: {jitter:.3f}",
                ),
            ],
            "model_version": "fft_beacon_detector_v1",
        }

    def detect(self, flow: Any) -> Optional[dict]:
        try:
            self._record_cross_flow(flow)
            src = getattr(flow, "src_ip", "") or ""
            dst = getattr(flow, "dst_ip", "") or ""
            dport = getattr(flow, "dst_port", None)
            pair_key = f"{src}|{dst}|{dport}"
            dst_key = f"{dst}|{dport}"

            # Cross-flow toward a small dest set (primary, matches PS)
            cross_min = max(4, min(self.min_observations, 5))
            result = self._beacon_from_series(self._pair_starts.get(pair_key, []), cross_min)
            if result is None:
                result = self._beacon_from_series(self._dst_starts.get(dst_key, []), cross_min)
            if result is not None:
                return result

            # Intra-flow packet timing (secondary)
            timestamps = getattr(flow, "timestamps", []) or []
            pkt_count = getattr(flow, "packet_count", 0) or 0
            if len(timestamps) < self.min_observations:
                return None
            arrival_times = compute_inter_arrival_times(timestamps)
            if not arrival_times:
                return None
            cv = compute_coefficient_of_variation(arrival_times)
            dur = flow.duration_seconds() if hasattr(flow, "duration_seconds") else 60.0
            if callable(dur):
                dur = dur()
            sample_rate = float(pkt_count) / max(float(dur), 1.0)
            fft_result = compute_fft_periodicity(timestamps, sample_rate=sample_rate)
            periodicity_score = fft_result["periodicity_score"]
            dominant_period = fft_result["dominant_period"]
            timing_consistency = 1.0 - min(cv, 1.0)
            # Constant IAT => FFT DC only; still a beacon if CV is tiny and interval is C2-like
            if cv < 0.1 and (periodicity_score > 0.2 or float(dur) >= 8.0):
                confidence = round(max(periodicity_score * 0.5 * timing_consistency, timing_consistency * 0.7), 4)
                severity = "high" if confidence > 0.4 else "medium"
                return {
                    "threat_class": "c2_beacon",
                    "severity": severity,
                    "confidence": confidence,
                    "evidence": [
                        Evidence(feature_name="periodicity_score", value=periodicity_score, contribution=0.4, description=f"Beacon periodicity score: {periodicity_score:.3f} (dominant period: {dominant_period:.1f}s)"),
                        Evidence(feature_name="inter_arrival_cv", value=cv, contribution=0.3, description=f"Inter-arrival coefficient of variation: {cv:.3f} (periodic if < 0.1)"),
                        Evidence(feature_name="dominant_period", value=round(dominant_period, 2), contribution=0.2, description=f"Dominant beacon interval: {dominant_period:.1f}s"),
                        Evidence(feature_name="jitter", value=round(1.0 - cv, 3), contribution=0.1, description=f"Timing consistency: jitter = {round(1.0 - cv, 3):.3f}"),
                    ],
                    "model_version": "fft_beacon_detector_v1",
                }
        except Exception:
            pass
        return None
