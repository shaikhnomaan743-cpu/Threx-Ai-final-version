from __future__ import annotations

import math
import time
from collections import deque, defaultdict
from typing import Dict, List, Any, Optional

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from app.config import settings
from app.alerts.schema import Evidence

# Amplification-capable service ports. A high request rate toward one of
# these from a single source is itself suspicious on a one-way tap, without
# ever needing to see the (possibly huge) response that a reflector sends
# back — which a unidirectional link cannot observe anyway.
AMPLIFIER_PORTS = {53, 123, 161, 389, 1900, 11211}

# One-sided rate thresholds. These are the same thresholds validated by
# scripts/run_ablation.py's one_sided_rules() against the lab corpus, ported
# here so the live detector and the ablation measurement describe the same
# system. Previously they did not: run_ablation.py scored a one-sided rule
# path that the deployed detector never ran.
# One-sided rate threshold. 111 pps is not an arbitrary round number: it is
# the midpoint of the gap between the highest packet rate in the labelled
# recon/port-scan corpus (110.6 pps) and the lowest in the labelled DDoS
# corpus (112.2 pps) — the two classes that actually compete for this rule
# on the lab data. Re-tune scripts/train_ddos.py against a larger corpus
# before trusting this exact value outside the lab set.
RATE_THRESHOLD = 111.0
AMP_RATE_THRESHOLD = 20.0

# A sustained high rate of small packets is what a SYN flood or a spoofed
# request flood actually looks like on the wire — the SYN packets themselves
# carry no payload. A rate spike made of large packets is far more likely a
# legitimate burst (a real transfer, a backup job) than a flood, so it is
# excluded here rather than left for the analyst to notice. This threshold
# is deliberately generous (flood packets in the lab corpus average 60
# bytes; ordinary payload-carrying packets in the benign corpus range
# 88-1,473 bytes) so it only excludes clearly non-flood-shaped traffic.
SMALL_PACKET_CEILING = 300.0


class DDOSDetector:
    """Volumetric / protocol DDoS detector — PS item (a).

    Reads only packet_rate, byte_rate and source-IP entropy: three
    quantities observable from the outbound direction alone. Earlier this
    detector's primary rule branch keyed off syn_to_ack_ratio and
    amplification_ratio, both of which require seeing the return direction
    a data diode physically removes. On the lab corpus those two-sided
    fields were also populated to a fixed synthetic value (9.0, just under
    the 10.0 rule threshold), so the rule branch never fired and every
    flow fell through to a weakly-calibrated IsolationForest — the SYN
    flood test set scored 0.000 F1 despite an AUC of 0.85, because the
    ranking was right but nothing ever crossed the alerting threshold.
    """

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

        # Real per-destination source-IP diversity tracker, replacing the
        # extract_ddos_features() stub that returned entropy_src_ips: 0.0
        # unconditionally. Keyed by destination IP; each entry is a bounded
        # deque of (timestamp, source_ip) seen targeting that destination.
        # This needs no return path — it is built entirely from source
        # addresses the diode already copies to us.
        self._dst_window: Dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
        self._window_seconds = 30.0

        # Calibration reference for the IsolationForest path: the min/max
        # decision_function score observed at fit time. Confidence is scaled
        # against this range instead of a fixed `* 2`, which assumed a score
        # magnitude the fitted model does not actually produce.
        self._score_lo: float = -0.2
        self._score_hi: float = 0.2

    def set_calibration(self, score_lo: float, score_hi: float):
        """Called after fitting with the training set's score range."""
        if score_hi > score_lo:
            self._score_lo, self._score_hi = float(score_lo), float(score_hi)

    def _record_source(self, dst_ip: str, src_ip: str, now: float) -> None:
        """Append (now, src) to dst's window and prune it - the state update
        _source_ip_entropy always did, without computing the entropy. Entropy
        is only evidence on an alert, so it is computed lazily (_entropy_now)
        for the few flows that alert instead of for every flow (~150 us each)."""
        win = self._dst_window[dst_ip]
        win.append((now, src_ip))
        cutoff = now - self._window_seconds
        while win and win[0][0] < cutoff:
            win.popleft()
        self._rec_ops = getattr(self, "_rec_ops", 0) + 1
        if self._rec_ops % 50_000 == 0:     # forget destinations gone quiet
            for k in [k for k, w in self._dst_window.items() if not w or w[-1][0] < cutoff]:
                del self._dst_window[k]

    def _entropy_now(self, dst_ip: str) -> float:
        """Normalised source-IP entropy of dst's current window (the exact
        computation _source_ip_entropy performs after its update)."""
        win = self._dst_window.get(dst_ip) or ()
        if len(win) < 2:
            return 1.0
        counts: Dict[str, int] = {}
        for _, ip in win:
            counts[ip] = counts.get(ip, 0) + 1
        total = sum(counts.values())
        probs = [c / total for c in counts.values()]
        h = -sum(p * math.log2(p) for p in probs if p > 0)
        h_max = math.log2(len(counts)) if len(counts) > 1 else 1.0
        return h / h_max if h_max > 0 else 1.0

    def _source_ip_entropy(self, dst_ip: str, src_ip: str, now: float) -> float:
        """Shannon entropy of source IPs seen hitting `dst_ip` in the last
        `_window_seconds`, normalised to [0, 1] by the max possible entropy
        for however many distinct sources were observed.

        A single source hammering one destination -> entropy near 0.
        Many distinct spoofed/botnet sources -> entropy near 1.
        Either extreme away from ordinary many-small-flows traffic is a
        DDoS signal; this function reports the raw normalised entropy and
        callers decide what range counts as anomalous.
        """
        win = self._dst_window[dst_ip]
        win.append((now, src_ip))
        cutoff = now - self._window_seconds
        while win and win[0][0] < cutoff:
            win.popleft()
        if len(win) < 2:
            return 1.0  # too little context to call it anomalous either way
        counts: Dict[str, int] = {}
        for _, ip in win:
            counts[ip] = counts.get(ip, 0) + 1
        total = sum(counts.values())
        probs = [c / total for c in counts.values()]
        h = -sum(p * math.log2(p) for p in probs if p > 0)
        h_max = math.log2(len(counts)) if len(counts) > 1 else 1.0
        return h / h_max if h_max > 0 else 1.0

    @staticmethod
    def _rate_confidence(rate: float, threshold: float, ceiling: float) -> float:
        """Map a one-sided rate to confidence in [0.5, 1.0] once it clears
        `threshold`, saturating at `ceiling`. 0.5 at the threshold itself
        (this is the point where we alert at all) rising smoothly, rather
        than dividing by an arbitrary constant that could land anywhere.
        """
        if rate <= threshold:
            return 0.0
        span = max(ceiling - threshold, 1e-6)
        frac = min(1.0, (rate - threshold) / span)
        return round(0.5 + 0.5 * frac, 4)

    def _one_sided_score(self, flow: Any, pkt_rate: float, byte_rate: float, avg_pkt_size: float) -> Optional[dict]:
        dst_ip = getattr(flow, "dst_ip", getattr(flow, "destination_ip", "?"))
        src_ip = getattr(flow, "src_ip", getattr(flow, "source_ip", "?"))
        dst_port = int(getattr(flow, "dst_port", getattr(flow, "destination_port", 0)) or 0)
        self._record_source(dst_ip, src_ip, time.time())

        # Sustained one-way packet rate: a SYN flood or any single-source
        # volumetric flood shows up here without ever needing the ACK side.
        # Gated on small average packet size (see SMALL_PACKET_CEILING) so a
        # legitimate large-packet burst is not mistaken for a flood.
        if pkt_rate > RATE_THRESHOLD and avg_pkt_size < SMALL_PACKET_CEILING:
            entropy = self._entropy_now(dst_ip)
            conf = self._rate_confidence(pkt_rate, RATE_THRESHOLD, RATE_THRESHOLD * 20)
            return {
                "threat_class": "ddos", "severity": "high" if conf > 0.75 else "medium",
                "confidence": conf,
                "evidence": [
                    Evidence(feature_name="packet_rate", value=round(pkt_rate, 2), contribution=0.55,
                             description=f"Sustained one-way packet rate {pkt_rate:.1f} pps (threshold {RATE_THRESHOLD:.0f} pps)"),
                    Evidence(feature_name="byte_rate", value=round(byte_rate, 2), contribution=0.20,
                             description=f"Byte rate {byte_rate:.1f} B/s"),
                    Evidence(feature_name="avg_packet_size", value=round(avg_pkt_size, 1), contribution=0.10,
                             description=f"Average packet size {avg_pkt_size:.0f} B (small, flood-shaped)"),
                    Evidence(feature_name="src_ip_entropy", value=round(entropy, 3), contribution=0.15,
                             description=f"Source-IP entropy toward this destination: {entropy:.2f} (0=single source, 1=maximally diverse)"),
                ],
                "model_version": "one_sided_rate_v2",
            }

        # Amplification without the response: a high request rate toward a
        # known amplifier port is itself suspicious — we never need to see
        # the (much larger) reply a diode cannot show us anyway.
        #
        # Gated on UDP + small packets because port 53 is also where DNS
        # tunnelling lives, and tunnelling traffic can hit the same rate
        # range. The two are distinguishable on features a one-way tap can
        # see: a reflection request is a short, fixed-shape query (~60 B in
        # this corpus); a tunnel carries encoded payload in the query name,
        # so its packets run larger (359-1,178 B in the labelled set) and
        # its own detector (DnsTunnelDetector) already handles it. Without
        # this gate the two rules fought over the same port-53 traffic.
        proto = str(getattr(flow, "protocol", "")).lower()
        if (dst_port in AMPLIFIER_PORTS and pkt_rate > AMP_RATE_THRESHOLD
                and proto == "udp" and avg_pkt_size < SMALL_PACKET_CEILING):
            entropy = self._entropy_now(dst_ip)
            conf = self._rate_confidence(pkt_rate, AMP_RATE_THRESHOLD, AMP_RATE_THRESHOLD * 20)
            return {
                "threat_class": "ddos", "severity": "medium",
                "confidence": conf,
                "evidence": [
                    Evidence(feature_name="packet_rate", value=round(pkt_rate, 2), contribution=0.6,
                             description=f"Request rate to amplifier port {dst_port}: {pkt_rate:.1f} req/s"),
                    Evidence(feature_name="src_ip_entropy", value=round(entropy, 3), contribution=0.4,
                             description=f"Source-IP entropy toward this destination: {entropy:.2f}"),
                ],
                "model_version": "one_sided_amplifier_v2",
            }
        return None

    def _forest_score(self, pkt_rate: float, byte_rate: float) -> Optional[float]:
        if not self.is_fitted or pkt_rate < 20:
            return None
        try:
            scaled = self.scaler.transform(np.array([[pkt_rate, byte_rate]], dtype=float))
            return float(self.iforest.decision_function(scaled)[0])
        except Exception:
            return None

    def _forest_confidence(self, anomaly_score: float) -> float:
        """Alert only when more anomalous than every flow in the benign
        calibration set, not merely on any negative score.

        The previous version fired whenever anomaly_score < 0 and floored
        confidence at 0.5 unconditionally — so a score barely negative
        (well within ordinary variance) still generated a 0.500-confidence
        alert. Real IsolationForest output on this feature pair had scores
        that were negative for a meaningful fraction of ordinary benign
        traffic (that is what "moderately below the training mean" looks
        like to an isolation-based scorer), so this was firing on noise.
        The gate is now `anomaly_score < score_lo`, i.e. more anomalous than
        the single most anomalous-looking benign reference flow.
        """
        if anomaly_score >= self._score_lo:
            return 0.0
        span = max(self._score_hi - self._score_lo, 1e-6)
        frac = min(1.0, (self._score_lo - anomaly_score) / span)
        return round(0.5 + 0.5 * frac, 4)

    def detect(self, flow: Any) -> Optional[dict]:
        try:
            pkt_rate = flow.packet_count / max(flow.duration_seconds(), 1.0) if hasattr(flow, "packet_count") else 0.0
            byte_rate = flow.bytes_transferred / max(flow.duration_seconds(), 1.0) if hasattr(flow, "bytes_transferred") else 0.0
            avg_pkt_size = (getattr(flow, "bytes_transferred", 0) or 0) / max(getattr(flow, "packet_count", 0) or 0, 1)

            hit = self._one_sided_score(flow, pkt_rate, byte_rate, avg_pkt_size)
            if hit:
                return hit

            score = self._forest_score(pkt_rate, byte_rate)
            if score is not None and score < self._score_lo:
                confidence = self._forest_confidence(score)
                if confidence >= 0.5:
                    return {
                        "threat_class": "ddos",
                        "severity": "high" if confidence > 0.75 else "medium",
                        "confidence": confidence,
                        "evidence": [
                            Evidence(feature_name="packet_rate", value=round(pkt_rate, 2), contribution=0.4, description=f"Anomalous packet rate: {pkt_rate:.1f} pps"),
                            Evidence(feature_name="byte_rate", value=round(byte_rate, 2), contribution=0.4, description=f"Anomalous byte rate: {byte_rate:.1f} B/s"),
                            Evidence(feature_name="isolation_forest_score", value=round(score, 4), contribution=0.2, description="IsolationForest anomaly score (negative = attack)"),
                        ],
                        "model_version": "isolation_forest_v2",
                    }
        except Exception:
            pass
        return None

    def detect_batch(self, flows: List[Any]) -> List[Optional[dict]]:
        """Same logic as detect(), batching only the IsolationForest call.

        The one-sided rate rule and the source-IP entropy tracker are cheap
        per-flow Python and run exactly as in detect(); only the sklearn
        call is grouped across the batch, since its per-call overhead is
        largely fixed regardless of row count.
        """
        results: List[Optional[dict]] = [None] * len(flows)
        model_indices: List[int] = []
        model_rows: List[List[float]] = []
        model_meta: List[tuple] = []

        for i, flow in enumerate(flows):
            try:
                pkt_rate = flow.packet_count / max(flow.duration_seconds(), 1.0) if hasattr(flow, "packet_count") else 0.0
                byte_rate = flow.bytes_transferred / max(flow.duration_seconds(), 1.0) if hasattr(flow, "bytes_transferred") else 0.0
                avg_pkt_size = (getattr(flow, "bytes_transferred", 0) or 0) / max(getattr(flow, "packet_count", 0) or 0, 1)

                hit = self._one_sided_score(flow, pkt_rate, byte_rate, avg_pkt_size)
                if hit:
                    results[i] = hit
                    continue

                if self.is_fitted and pkt_rate >= 20:
                    model_indices.append(i)
                    model_rows.append([pkt_rate, byte_rate])
                    model_meta.append((pkt_rate, byte_rate))
            except Exception:
                continue

        if model_rows:
            try:
                X = np.array(model_rows, dtype=float)
                scaled = self.scaler.transform(X)
                scores = self.iforest.decision_function(scaled)
                for j, i in enumerate(model_indices):
                    anomaly_score = float(scores[j])
                    if anomaly_score < self._score_lo:
                        confidence = self._forest_confidence(anomaly_score)
                        if confidence < 0.5:
                            continue
                        pkt_rate, byte_rate = model_meta[j]
                        results[i] = {
                            "threat_class": "ddos",
                            "severity": "high" if confidence > 0.75 else "medium",
                            "confidence": confidence,
                            "evidence": [
                                Evidence(feature_name="packet_rate", value=round(pkt_rate, 2), contribution=0.4, description=f"Anomalous packet rate: {pkt_rate:.1f} pps"),
                                Evidence(feature_name="byte_rate", value=round(byte_rate, 2), contribution=0.4, description=f"Anomalous byte rate: {byte_rate:.1f} B/s"),
                                Evidence(feature_name="isolation_forest_score", value=round(anomaly_score, 4), contribution=0.2, description="IsolationForest anomaly score (negative = attack)"),
                            ],
                            "model_version": "isolation_forest_v2",
                        }
            except Exception:
                pass
        return results


_detector_instances: Dict[str, DDOSDetector] = {}

def get_ddos_detector(protocol: str = "tcp") -> DDOSDetector:
    if protocol not in _detector_instances:
        _detector_instances[protocol] = DDOSDetector(contamination=settings.ddos_contamination)
    return _detector_instances[protocol]
