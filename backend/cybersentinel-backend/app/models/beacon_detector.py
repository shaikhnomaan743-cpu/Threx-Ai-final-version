from __future__ import annotations

import bisect
import math
import time as _time

import numpy as np
from scipy.fft import fft as _scipy_fft

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


# Array versions of beacon_features' helpers. Same operations in the same
# order (elementwise IEEE subtraction, numpy mean/std on identical values), so
# results are bit-identical; the inter-arrival array is built once per series
# instead of three times through a Python loop.
def _iats(ts) -> np.ndarray:
    x = np.asarray(ts, dtype=float)
    return x[1:] - x[:-1] if x.size >= 2 else np.empty(0)


def _cv(a: np.ndarray) -> float:
    if a.size < 2:
        return 1.0
    m = a.mean()
    if m == 0:
        return 1.0
    s = a.std(ddof=1)
    if s == 0:
        return 0.0
    return float(s / m)


def _fft_periodicity(a: np.ndarray, sample_rate: float = 1.0) -> dict:
    zero = {"dominant_freq": 0.0, "periodicity_score": 0.0, "dominant_period": 0.0, "fft_power": 0.0}
    if a.size < 4:
        return zero
    arr = a[a > 0]
    if arr.size < 4:
        return zero
    powers = np.abs(_scipy_fft(arr)[:arr.size // 2]) ** 2
    if len(powers) > 1:
        idx = np.argmax(powers[1:]) + 1
        freq = float(idx * sample_rate / arr.size)
        dom = float(powers[idx])
    else:
        freq, dom = 0.0, 0.0
    total = np.sum(powers)
    score = dom / total if total > 0 else 0.0
    return {"dominant_freq": freq, "periodicity_score": float(score),
            "dominant_period": 1.0 / freq if freq > 0 else 0.0, "fft_power": dom}


def _jitter(a: np.ndarray) -> float:
    if a.size < 2:
        return 1.0
    m = a.mean()
    if m == 0:
        return 1.0
    return float(np.abs(a - m).mean()) / m


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
        self._dst_sources: Dict[str, set] = defaultdict(set)
        self._last_update: Dict[str, float] = {}
        self._dst_seen: set = set()
        self._ops = 0
        self.state_ttl_s = 3600.0
        self.max_pairs = 250_000
        # Multi-core: when True, detect() runs only the per-pair check and
        # leaves (dst_key, start, src, eligible) in _last_dst_event for the
        # destination aggregator. Single-process behaviour is unchanged.
        self.defer_dst_level = False
        self._last_dst_event = None
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
        # Sorted insert + trim == sorted(list + [start])[-64:], without a
        # full re-sort per flow.
        ps = self._pair_starts[pair_key]
        bisect.insort(ps, start)
        if len(ps) > 64:
            del ps[:-64]
        self._touch(pair_key, dst_key)

        pkt_count = int(getattr(flow, "packet_count", 0) or 0)
        bytes_xfer = int(getattr(flow, "bytes_transferred", 0) or 0)
        eligible = pkt_count <= 40 and bytes_xfer < 25_000
        if self.defer_dst_level:
            # Multi-core mode: destination-level state lives in the dst
            # aggregator (app/ingest/parallel.py), which sees every source.
            self._last_dst_event = (dst_key, start, src, eligible)
            return
        # Sparse sessions (classic beacon) — exclude bulk TLS/exfil to same dest
        if eligible:
            ds = self._dst_starts[dst_key]
            bisect.insort(ds, start)
            if len(ds) > 128:
                del ds[:-128]
            srcs = self._dst_sources[dst_key]
            if len(srcs) < 2:               # only ">= 2 distinct sources" is ever read
                srcs.add(src)

    # ---- destination-level check, run by the dst aggregator in multi-core mode
    def dst_event(self, dst_key: str, start: float, src: str, eligible: bool,
                  pair_hit: bool) -> Optional[dict]:
        """Exactly the destination-level half of detect(): record the flow's
        start (if it is a sparse session), then - only if the per-pair check
        did not already alert - test the destination series under the same
        >= 2 distinct sources fan-in gate."""
        if eligible:
            ds = self._dst_starts[dst_key]
            bisect.insort(ds, start)
            if len(ds) > 128:
                del ds[:-128]
            srcs = self._dst_sources[dst_key]
            if len(srcs) < 2:
                srcs.add(src)
            now = _time.monotonic()
            self._last_update.pop(dst_key, None)
            self._last_update[dst_key] = now
            self._ops += 1
            if self._ops % 50_000 == 0:          # forget idle destinations
                cutoff = now - self.state_ttl_s
                for k in [k for k, t in self._last_update.items() if t < cutoff]:
                    self._last_update.pop(k, None)
                    self._dst_starts.pop(k, None)
                    self._dst_sources.pop(k, None)
        if pair_hit:
            return None
        if len(self._dst_sources.get(dst_key, ())) >= 2:
            cross_min = max(4, min(self.min_observations, 5))
            return self._beacon_from_series(self._dst_starts.get(dst_key, []), cross_min)
        return None

    def _touch(self, pair_key: str, dst_key: str) -> None:
        """Memory bound for streaming: remember when each key was last fed and
        periodically forget keys idle longer than `state_ttl_s` (default 1 h,
        longer than typical beacon intervals), and cap the number of pair keys
        (oldest-updated evicted first). Previously these dicts grew forever -
        at 100k+ flows/s of mostly unique pairs that is unbounded memory."""
        now = _time.monotonic()
        lu = self._last_update
        lu.pop(pair_key, None)
        lu[pair_key] = now
        self._ops += 1
        if self._ops % 50_000 == 0:
            cutoff = now - self.state_ttl_s
            stale = []
            for k, t in lu.items():          # insertion order == update order
                if t >= cutoff and len(lu) - len(stale) <= self.max_pairs:
                    break
                stale.append(k)
            for k in stale:
                lu.pop(k, None)
                self._pair_starts.pop(k, None)
                d = k.split("|", 1)[1] if "|" in k else k
                self._dst_seen.discard(d)
            if len(self._dst_starts) > 2 * self.max_pairs or stale:
                live = {k.split("|", 1)[1] for k in lu}
                for d in [d for d in self._dst_starts if d not in live]:
                    self._dst_starts.pop(d, None)
                    self._dst_sources.pop(d, None)

    def _beacon_from_series(self, timestamps: List[float], min_obs: int) -> Optional[dict]:
        if len(timestamps) < min_obs:
            return None
        ts = sorted(timestamps)
        if len(ts) - 1 < max(2, min_obs - 1):
            return None
        # Cheap pure-Python pre-filter (numpy's std on a <=128-element array
        # is ~30 us of call overhead). It only REJECTS series clearly above
        # the cv < 0.25 gate (1e-6 relative margin >> float rounding); anything
        # near or below falls through to the exact numpy path unchanged.
        iats = [b - a_ for a_, b in zip(ts, ts[1:])]
        m = sum(iats) / len(iats)
        if m <= 0:
            return None                      # _cv() -> 1.0 -> not < 0.25
        v = sum((x - m) * (x - m) for x in iats) / (len(iats) - 1)
        if math.sqrt(v) / m > 0.25 * (1 + 1e-6):
            return None
        a = np.asarray(iats, dtype=float)
        cv = _cv(a)
        # is_periodic below needs cv < 0.25 in both of its branches, so a
        # series at or above that can never alert: skip the FFT and jitter
        # work (most series) - identical outcome, a fraction of the cost.
        if not cv < 0.25:
            return None
        mean_iat = float(sum(a.tolist()) / a.size) if a.size else 0.0
        # Parseval bound: the FFT periodicity score of the positive IATs is
        # <= var_pop/mean^2 of those IATs (dominant non-DC power <= total
        # non-DC power = n*sum((x-mean)^2); denominator >= DC power =
        # (sum x)^2). With all IATs positive that is ((n-1)/n)*cv^2 < 0.0625
        # for cv < 0.25, so the "cv < 0.25 and score > 0.2" branch cannot
        # fire; only "cv < 0.15 and mean >= 0.4" can. Skip the FFT when that
        # branch is also false - provably identical outcome.
        if not (cv < 0.15 and mean_iat >= 0.4) and bool((a > 0).all()):
            return None
        sample_rate = 1.0 / max(mean_iat, 1e-6)
        fft_result = _fft_periodicity(a, sample_rate=sample_rate)
        periodicity_score = float(fft_result["periodicity_score"])
        dominant_period = float(fft_result["dominant_period"] or mean_iat)
        timing_consistency = 1.0 - min(cv, 1.0)
        jitter = _jitter(a)

        # Perfectly regular series put FFT energy in DC — CV is the reliable signal.
        is_periodic = (cv < 0.15 and mean_iat >= 0.4) or (cv < 0.25 and periodicity_score > 0.2)
        if not is_periodic:
            return None

        confidence = round(min(1.0, (timing_consistency * 0.6) + min(periodicity_score, 1.0) * 0.4), 4)
        if confidence < 0.35:
            confidence = round(min(1.0, timing_consistency * 0.7), 4)
        if confidence < 0.35:
            return None
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
        self._last_dst_event = None
        try:
            # DNS exclusion: DNS query/response traffic toward port 53 is
            # periodic by construction, so it falsely trips the cross-flow
            # periodicity check and is scored as c2_beacon. DNS beaconing is
            # already covered by the DGA and DNS-tunnel detectors, so skip
            # beacon detection on port 53 (both directions).
            dport = getattr(flow, "dst_port", None)
            sport = getattr(flow, "src_port", None)
            if dport == 53 or sport == 53:
                return None

            self._record_cross_flow(flow)
            src = getattr(flow, "src_ip", "") or ""
            dst = getattr(flow, "dst_ip", "") or ""
            pair_key = f"{src}|{dst}|{dport}"
            dst_key = f"{dst}|{dport}"

            cross_min = max(4, min(self.min_observations, 5))
            result = self._beacon_from_series(self._pair_starts.get(pair_key, []), cross_min)
            if result is None and not self.defer_dst_level:
                dst_entries = self._dst_starts.get(dst_key, [])
                dst_sources = self._dst_sources.get(dst_key, set())
                # Fan-in gating: only flag destination-level periodicity if
                # multiple distinct sources are contacting the same destination.
                # This prevents single-source periodic traffic (NTP, telemetry)
                # from falsely triggering as C2 beaconing.
                if len(dst_sources) >= 2:
                    result = self._beacon_from_series(dst_entries, cross_min)
                else:
                    # Still record the start time even without fan-in, so the
                    # intra-flow secondary check can still run later
                    pass
            if result is not None:
                return result

            # Intra-flow packet timing (secondary, fan-in gated).
            repeat_to_dest = (
                len(self._pair_starts.get(pair_key, [])) >= 2
                or len(self._dst_starts.get(dst_key, [])) >= 2
            )
            if not repeat_to_dest:
                return None

            timestamps = getattr(flow, "timestamps", []) or []
            pkt_count = getattr(flow, "packet_count", 0) or 0
            if len(timestamps) < self.min_observations:
                return None
            # PROVABLY DEAD BRANCH (reported, behaviour preserved): alerting
            # needs cv < 0.05 AND periodicity_score > 0.3, but by the Parseval
            # bound score <= var_pop/mean^2 = ((n-1)/n)*cv^2 < 0.0025 when all
            # IATs are positive. With <= 64 timestamps and a positive mean, a
            # single non-positive IAT forces cv >= 1/sqrt(63) = 0.126, so
            # cv < 0.05 implies all IATs positive. Hence no alert is possible
            # here in that regime; return early instead of computing it.
            # (Outside it - >64 timestamps or a non-positive mean - the
            # original computation below still runs unchanged.)
            if 2 <= len(timestamps) <= 64:
                span = timestamps[-1] - timestamps[0]
                if span > 0:
                    return None
            a = _iats(timestamps)
            if not a.size:
                return None
            cv = _cv(a)
            if not cv < 0.05:               # the only alerting branch needs cv < 0.05
                return None
            dur = flow.duration_seconds() if hasattr(flow, "duration_seconds") else 60.0
            if callable(dur):
                dur = dur()
            sample_rate = float(pkt_count) / max(float(dur), 1.0)
            fft_result = _fft_periodicity(a, sample_rate=sample_rate)
            periodicity_score = fft_result["periodicity_score"]
            dominant_period = fft_result["dominant_period"]
            timing_consistency = 1.0 - min(cv, 1.0)
            if cv < 0.05 and periodicity_score > 0.3:
                confidence = round(max(periodicity_score * 0.5 * timing_consistency, timing_consistency * 0.7), 4)
                severity = "high" if confidence > 0.4 else "medium"
                return {
                    "threat_class": "c2_beacon",
                    "severity": severity,
                    "confidence": confidence,
                    "evidence": [
                        Evidence(feature_name="periodicity_score", value=periodicity_score, contribution=0.4,
                                 description=f"Beacon periodicity score: {periodicity_score:.3f} (dominant period: {dominant_period:.1f}s)"),
                        Evidence(feature_name="inter_arrival_cv", value=cv, contribution=0.3,
                                 description=f"Inter-arrival coefficient of variation: {cv:.3f} (periodic if < 0.1)"),
                        Evidence(feature_name="dominant_period", value=round(dominant_period, 2), contribution=0.2,
                                 description=f"Dominant beacon interval: {dominant_period:.1f}s"),
                        Evidence(feature_name="jitter", value=round(1.0 - cv, 3), contribution=0.1,
                                 description=f"Timing consistency: jitter = {round(1.0 - cv, 3):.3f}"),
                    ],
                    "model_version": "fft_beacon_detector_v1",
                }
        except Exception:
            pass
        return None

