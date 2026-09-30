from __future__ import annotations

import asyncio
import json
import time
import uuid
import logging
from typing import Dict, List, Any, Optional, Tuple

import numpy as np

from app.config import settings
from app.alerts.schema import Alert, Evidence
from app.models.ddos_detector import DDOSDetector, get_ddos_detector
from app.models.beacon_detector import BeaconDetector
from app.models.dga_classifier import predict_dga, train_dga_model, load_alexa_top_1m, load_dgarchive_samples, extract_dga_domain_features
from app.models.tls_classifier import TLSMalwareClassifier, get_tls_malware_classifier
from app.models.scan_detector import ScanDetector, get_scan_detector
from app.models.exfil_detector import ExfiltrationDetector
from app.models.dns_tunnel_detector import DnsTunnelDetector
from app.models.slowloris_detector import SlowRateDoSDetector

logger = logging.getLogger(__name__)


# Two-level public suffixes common in the corpus / Indian and CI traffic. Not a
# full Public Suffix List (no extra dependency); unknown suffixes fall back to
# "second-to-last label", which is correct for all single-level TLDs.
_MULTI_PART_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "net.uk", "co.in", "net.in", "org.in",
    "gov.in", "ac.in", "nic.in", "res.in", "edu.in", "com.au", "net.au", "org.au",
    "edu.au", "gov.au", "co.jp", "ne.jp", "or.jp", "com.br", "net.br", "com.cn",
    "net.cn", "org.cn", "com.ar", "co.za", "com.mx", "com.tr", "co.kr", "com.sg",
    "com.hk", "com.tw", "co.nz", "com.my", "co.id", "com.pk", "com.ua", "com.ru",
})


def _flow_meta(flow: Any) -> tuple:
    """What an aggregator needs to build/backfill an alert for this flow."""
    dur = getattr(flow, "duration_seconds", 0.0)
    dur = dur() if callable(dur) else dur
    return (getattr(flow, "key", None), getattr(flow, "src_ip", ""), getattr(flow, "dst_ip", ""),
            getattr(flow, "src_port", None), getattr(flow, "dst_port", None),
            getattr(flow, "protocol", "tcp"), int(getattr(flow, "bytes_transferred", 0) or 0),
            int(getattr(flow, "packet_count", 0) or 0), float(dur or 0.0))


def backfill_alert(alert: Any, flow_key: Any, src_ip: str, dst_ip: str) -> Any:
    """Same backfill the pipeline applies before dispatch (pipeline._dispatch_alerts)."""
    if not getattr(alert, "source_ip", None) or alert.source_ip == "0.0.0.0":
        alert.source_ip = src_ip or alert.source_ip
    if not getattr(alert, "destination_ip", None) or alert.destination_ip == "0.0.0.0":
        alert.destination_ip = dst_ip or alert.destination_ip
    if not getattr(alert, "flow_id", None):
        alert.flow_id = flow_key or alert.alert_id
    return alert


def _registrable_label(domain: str) -> str:
    """'www.google.co.uk' -> 'google'; 'jusblkekwjj.ru' -> 'jusblkekwjj'."""
    labels = [l for l in (domain or "").strip().lower().rstrip(".").split(".") if l]
    if len(labels) <= 1:
        return labels[0] if labels else ""
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_PART_SUFFIXES:
        return labels[-3]
    return labels[-2]



class InferenceEngine:
    """Orchestrates all 6 threat detectors in parallel.

    Takes a flow, extracts features, runs all detectors asynchronously,
    and combines results into unified alerts.
    """

    def __init__(self):
        self.detectors: Dict[str, Any] = {
            "ddos": get_ddos_detector(),
            "beacon": BeaconDetector(),
            "dga": None,  # Will be set after model training
            "tls": get_tls_malware_classifier(),
            "scan": get_scan_detector(),
            "exfil": ExfiltrationDetector(),
            "dns_tunnel": DnsTunnelDetector(),
            # Slow-rate DoS (Slowloris); reports as threat_class "ddos".
            "slowloris": SlowRateDoSDetector(),
        }
        self._model_loaded: Dict[str, bool] = {
            "dga": False,
        }
        # Multi-core mode (app/ingest/parallel.py): destination-level C2 state
        # is evaluated by a dst aggregator; the batch path queues events here.
        self.defer_dst_level = False
        self.pending_dst_events: List[tuple] = []
        self._lock = asyncio.Lock()

    def _calibrate_ddos(self, det) -> None:
        """Score the real benign lab corpus through the fitted forest and use
        its decision_function range as the calibration reference, so
        confidence reflects how anomalous a flow is relative to traffic we
        actually observed, not an assumption about the training data's scale.
        """
        import os, json
        import numpy as np
        candidates = [
            os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "data", "pcaps", "benign", "benign_tcp.json"),
            os.path.join(settings.pcap_dir, "benign", "benign_tcp.json"),
        ]
        rows = None
        for c in candidates:
            if os.path.exists(c):
                rows = json.loads(open(c).read())
                break
        if not rows:
            return
        feats = []
        for f in rows:
            dur = max(float(f.get("duration_seconds") or 1.0), 1.0)
            pkt_rate = float(f.get("packet_count") or 0) / dur
            byte_rate = float(f.get("bytes_transferred") or 0) / dur
            feats.append([pkt_rate, byte_rate])
        if len(feats) < 5:
            return
        X = np.array(feats, dtype=float)
        scaled = det.scaler.transform(X)
        scores = det.iforest.decision_function(scaled)
        det.set_calibration(float(scores.min()), float(scores.max()))
        logger.info(
            "DDoS calibration: benign score range [%.4f, %.4f] over %d reference flows",
            scores.min(), scores.max(), len(feats),
        )

    async def initialize_models(self):
        import os, joblib
        # resolve artifacts_dir to absolute (handles cwd differences)
        artifacts_dir = settings.artifacts_dir
        if not os.path.isabs(artifacts_dir):
            # try relative to backend root, then to this file
            candidates = [
                artifacts_dir,
                os.path.join(os.getcwd(), artifacts_dir),
                os.path.join(os.path.dirname(__file__), "..", "models", "artifacts"),
                os.path.join(os.path.dirname(__file__), "..", "..", "app", "models", "artifacts"),
            ]
            for c in candidates:
                if os.path.exists(c):
                    artifacts_dir = c
                    break
            else:
                artifacts_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models", "artifacts"))
        os.makedirs(artifacts_dir, exist_ok=True)
        # DGA
        dga_path = os.path.join(artifacts_dir, "dga_classifier.joblib")
        if os.path.exists(dga_path):
            try:
                self.detectors["dga"] = joblib.load(dga_path)
                self._model_loaded["dga"] = True
                logger.info("DGA model loaded")
            except Exception as e:
                logger.warning(f"Failed to load DGA model: {e}")
        if not self._model_loaded["dga"]:
            await self._train_dga_model_async()
        # TLS
        tls_path = os.path.join(artifacts_dir, "tls_classifier.joblib")
        if os.path.exists(tls_path):
            try:
                tls_model = joblib.load(tls_path)
                self.detectors["tls"] = tls_model
                logger.info("TLS malware model loaded")
            except Exception as e:
                logger.warning(f"Failed to load TLS model: {e}")
        # DDoS
        ddos_path = os.path.join(artifacts_dir, "ddos_detector.joblib")
        if os.path.exists(ddos_path):
            try:
                data = joblib.load(ddos_path)
                det = get_ddos_detector()
                det.iforest = data["model"]
                det.scaler = data["scaler"]
                det.is_fitted = True
                logger.info("DDoS IsolationForest loaded")
                # Calibrate confidence scaling against the real benign lab
                # corpus rather than a fixed multiplier. The saved scaler's
                # training mean (~7,663 pps) does not resemble the pkt/byte
                # rates in our own lab traffic, so a confidence formula tuned
                # to the training distribution produced near-zero scores on
                # real test flows even when IsolationForest ranked them
                # correctly (AUC 0.85, but 0 alerts ever crossed threshold).
                try:
                    self._calibrate_ddos(det)
                except Exception as e:
                    logger.warning("DDoS calibration skipped: %s", e)
            except Exception as e:
                logger.warning(f"Failed to load DDoS model: {e}")
        # Exfil
        exfil_path = os.path.join(artifacts_dir, "exfil_detector.joblib")
        if os.path.exists(exfil_path):
            try:
                data = joblib.load(exfil_path)
                self.detectors["exfil"].iforest = data["model"]
                self.detectors["exfil"].scaler = data["scaler"]
                self.detectors["exfil"].is_fitted = True
                logger.info("Exfiltration IsolationForest loaded")
            except Exception as e:
                logger.warning(f"Failed to load Exfil model: {e}")
        try:
            with open(os.path.join(artifacts_dir, "evaluation.json")) as f:
                ed=json.load(f)
                logger.info(f"Models evaluation: DGA AUC {ed.get('detectors',{}).get('dga',{}).get('test_auc')} TLS AUC {ed.get('detectors',{}).get('tls_malware',{}).get('test_auc')}")
        except Exception:
            pass

    async def _train_dga_model_async(self):
        """Train DGA model asynchronously in background."""
        try:
            # Load training data
            benign_domains = load_alexa_top_1m()
            malicious_domains = load_dgarchive_samples()

            if benign_domains and malicious_domains:
                clf, train_auc, test_auc = train_dga_model(
                    benign_domains, malicious_domains
                )
                self.detectors["dga"] = clf
                self._model_loaded["dga"] = True
                logger.info(
                    f"DGA model trained: train AUC={train_auc:.4f}, test AUC={test_auc:.4f}"
                )
            else:
                logger.warning("Insufficient training data for DGA model")
        except Exception as e:
            logger.error(f"DGA model training failed: {e}")

    def enable_multicore(self) -> None:
        """Worker mode: per-pair C2 here, destination-level C2 in the dst
        aggregator (see app/ingest/parallel.py). Only the batch path queues
        destination events, and workers only use the batch path."""
        self.defer_dst_level = True
        b = self.detectors.get("beacon")
        if b is not None:
            b.defer_dst_level = True
        s = self.detectors.get("slowloris")
        if s is not None:
            s.defer_concurrency = True

    async def analyze_flow(self, flow: Any) -> List[Alert]:
        """Analyze a flow through all 6 detectors in parallel.

        Args:
            flow: FlowState object with accumulated packet metadata

        Returns:
            List of detected alerts (may be empty if no threats found)
        """
        # NOTE: this used to run inside `async with self._lock`, which forced
        # every flow to wait for the previous flow's detectors to fully finish
        # before starting its own — i.e. the whole pipeline was serialized on
        # a mutex protecting nothing, since none of the seven detectors share
        # mutable state with each other. The only detectors with any shared
        # state (beacon, scan) mutate flow-keyed dicts synchronously with no
        # `await` in between, so there's no interleaving hazard from processing
        # flows back-to-back without a lock. Removing it is what lets analyze_flow
        # calls for different flows actually run concurrently.
        tasks = [
            self._run_detector("ddos", flow),
            self._run_detector("beacon", flow),
            self._run_detector("dga", flow),
            self._run_detector("tls", flow),
            self._run_detector("scan", flow),
            self._run_detector("exfil", flow),
            self._run_detector("dns_tunnel", flow),
            self._run_detector("slowloris", flow),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=False)

        # Filter out None results and convert dicts to Alerts
        alerts = []
        for result in results:
            if result is None:
                continue
            if isinstance(result, dict):
                # Convert dict to Alert
                alert = self._dict_to_alert(result)
                if alert:
                    alerts.append(alert)
            elif isinstance(result, Alert):
                alerts.append(result)

        # Deduplicate alerts (same threat_class + source_ip + dst_ip)
        deduped = self._deduplicate_alerts(alerts)

        # Assign final confidence and severity
        for alert in deduped:
            self._finalize_alert(alert)

        return deduped

    async def analyze_flows_batch(self, flows: List[Any]) -> List[List[Alert]]:
        """Analyze many flows at once, batching the three sklearn-backed
        detectors (ddos, tls, exfil) into a single model call each instead of
        one call per flow. Per-row sklearn overhead (input validation, walking
        the trees) is largely fixed regardless of batch size, so this is the
        single biggest throughput lever in the pipeline — measured at roughly
        30-900x depending on batch size, on this project's own trained models.

        beacon/scan/dga/dns_tunnel are NOT batched here: beacon and scan carry
        cross-flow state that must be updated in the same order flows actually
        arrived in, dga/dns_tunnel are comparatively cheap per-flow calls that
        were never the bottleneck (profiling showed the two sklearn ensemble
        detectors were ~88% of per-flow detection time). Batching only where
        the win is real keeps this change small and easy to verify against the
        existing per-flow analyze_flow() path, which is left untouched and is
        still exactly what the test suite exercises.

        Returns one list of Alerts per input flow, in the same order as `flows`,
        identical in content to calling analyze_flow() on each flow one at a time.
        """
        n = len(flows)
        if n == 0:
            return []
        if n == 1 and not self.defer_dst_level:
            # (In multi-core mode even a single flow must take the batch path,
            # which is the one that queues destination-level C2 events.)
            return [await self.analyze_flow(flows[0])]

        ddos_det = self.detectors.get("ddos")
        tls_det = self.detectors.get("tls")
        exfil_det = self.detectors.get("exfil")

        ddos_results = ddos_det.detect_batch(flows) if ddos_det is not None and hasattr(ddos_det, "detect_batch") else [None] * n
        tls_results = tls_det.predict_batch(flows) if tls_det is not None and hasattr(tls_det, "predict_batch") else [None] * n
        exfil_results = exfil_det.detect_batch(flows) if exfil_det is not None and hasattr(exfil_det, "detect_batch") else [None] * n
        dga_pre = self._dga_batch(flows)

        out: List[List[Alert]] = []
        for idx, flow in enumerate(flows):
            # Stateful / cheap detectors still run one flow at a time, in
            # arrival order, so cross-flow state (beacon, scan) stays correct.
            # Awaited in sequence rather than via asyncio.gather: none of these
            # detectors ever suspends (no I/O), so gather ran them to
            # completion one after another in this same order anyway - it just
            # also created and scheduled five Tasks per flow (~20% of batch
            # time in profiling). Same order, same state updates, same results.
            beacon_res = await self._run_detector("beacon", flow)
            if self.defer_dst_level:
                ev = getattr(self.detectors.get("beacon"), "_last_dst_event", None)
                if ev is not None:
                    self.pending_dst_events.append((ev, beacon_res is not None, _flow_meta(flow)))
            dga_res = dga_pre[idx] if dga_pre is not None else await self._run_detector("dga", flow)
            scan_res = await self._run_detector("scan", flow)
            dns_res = await self._run_detector("dns_tunnel", flow)
            slow_res = await self._run_detector("slowloris", flow)
            if self.defer_dst_level:
                sev = getattr(self.detectors.get("slowloris"), "_last_event", None)
                if sev is not None:
                    self.pending_dst_events.append((("slow",) + sev, False, _flow_meta(flow)))

            # Reassembled in the SAME order analyze_flow() uses: ddos, beacon,
            # dga, tls, scan, exfil, dns_tunnel. This isn't cosmetic — when a
            # single flow raises more than one alert, the order they're handed
            # to AlertManager.add_alert() affects which existing alert a later
            # one gets matched/merged against (it scans active alerts and takes
            # the first dedup-key match). Keeping the same order here is what
            # makes this batch path produce identical AlertManager grouping to
            # the single-flow path for the same input, not just identical raw
            # per-flow detections.
            raw_results = [ddos_results[idx], beacon_res, dga_res, None, scan_res, exfil_results[idx], dns_res, slow_res]

            alerts = []
            for pos, result in enumerate(raw_results):
                if pos == 3:  # tls slot — handled separately below, needs `flow` for backfill
                    if tls_results[idx] is not None:
                        # Routed through the same converter as the single-flow
                        # path (_tls_result_to_alert), not the generic
                        # _dict_to_alert, so source_ip/destination_ip/flow_id
                        # are populated from the flow itself instead of
                        # defaulting to "0.0.0.0".
                        tls_alert = self._tls_result_to_alert(tls_results[idx], flow)
                        if tls_alert:
                            alerts.append(tls_alert)
                    continue
                if result is None:
                    continue
                if isinstance(result, dict):
                    alert = self._dict_to_alert(result)
                    if alert:
                        alerts.append(alert)
                elif isinstance(result, Alert):
                    alerts.append(result)

            deduped = self._deduplicate_alerts(alerts)
            for alert in deduped:
                self._finalize_alert(alert)
            out.append(deduped)
        return out

    async def _run_detector(
        self, detector_name: str, flow: Any
    ) -> Optional[Alert | dict]:
        """Run a single detector on a flow.

        Returns Alert dict or None.
        """
        try:
            detector = self.detectors.get(detector_name)
            if detector is None:
                return None

            if detector_name == "dga":
                # DGA detector needs a domain, not a flow
                # Extract domain from DNS queries in the flow
                domain = getattr(flow, 'dns_query', '') or ''
                if domain:
                    return await self._detect_dga_from_domain(domain, flow)
                return None

            if detector_name == "tls":
                try:
                    result = detector.predict(flow) if hasattr(detector, 'predict') else detector.detect(flow)
                except Exception:
                    result = None
                if result is None:
                    return None
                return self._tls_result_to_alert(result, flow)

            if detector_name == "scan":
                if hasattr(flow, "to_dict") and hasattr(detector, "detect_flow"):
                    # Incremental per-source table, no per-flow to_dict().
                    result = detector.detect_flow(flow)
                else:
                    flow_dict = dict(flow) if isinstance(flow, dict) else getattr(flow, '__dict__', {})
                    result = detector.detect(flow_dict, all_flows_from_src=None)
                if result is None:
                    return None
                return self._scan_result_to_alert(result, flow)

            if detector_name == "dns_tunnel":
                result = detector.detect(flow)
                if result is None:
                    return None
                return self._dict_to_alert(result)

            # For other detectors (ddos, beacon, exfil)
            result = detector.detect(flow) if hasattr(detector, 'detect') else None
            if result is None:
                return None
            if isinstance(result, dict):
                return self._dict_to_alert(result)
            return result

        except Exception as e:
            logger.error(f"Detector {detector_name} error: {e}", exc_info=True)
            return None

    async def _detect_dga_from_domain(self, domain: str, flow: Any = None) -> Optional[Alert]:
        """Detect DGA from a domain name."""
        try:
            model = self.detectors.get("dga")
            if model is None or self._model_loaded.get("dga", False) is False:
                return None

            # Score the registrable label, not the full FQDN: the model was trained
            # on bare labels ("google", not "www.google.com"). Scoring the FQDN
            # measured 80.4% held-out accuracy vs 97.05% for the label.
            result = predict_dga(model, _registrable_label(domain))
            return self._dga_alert(result)
        except Exception as e:
            logger.error(f"DGA detection error: {e}")
            return None

    def _dga_batch(self, flows: List[Any]) -> Optional[List[Optional[Alert]]]:
        """Score every DNS-bearing flow in the batch with ONE LightGBM call.

        Same inputs as the per-flow path: predict_dga()'s feature extractor
        and its exact 7-feature order (dga_classifier.py is not modified), so
        each row's probability is identical to scoring it alone - only the
        per-call overhead (~245 us/domain) is removed. Returns None on any
        problem so the caller falls back to the per-flow path.
        """
        try:
            model = self.detectors.get("dga")
            if model is None or self._model_loaded.get("dga", False) is False:
                return None
            out: List[Optional[Alert]] = [None] * len(flows)
            idx = [i for i, f in enumerate(flows) if (getattr(f, "dns_query", "") or "")]
            if not idx:
                return out
            feats = [extract_dga_domain_features(_registrable_label(flows[i].dns_query)) for i in idx]
            X = np.array([[f["domain_entropy"], f["bigram_log_likelihood_2"], f["bigram_log_likelihood_3"],
                           f["consonant_vowel_ratio"], f["digit_ratio"], f["tld_length"],
                           1 if f["has_dictionary_word"] else 0] for f in feats], dtype=float)
            probs = model.predict(X)
            for i, f, p in zip(idx, feats, probs):
                p = float(p)
                if p > 0.5:
                    out[i] = self._dga_alert({"domain": flows[i].dns_query, "is_dga": True,
                                              "dga_probability": p, "confidence": max(p, 1 - p),
                                              "features": f})
            return out
        except Exception as e:
            logger.debug("batched DGA scoring fell back to per-flow: %s", e)
            return None

    def _dga_alert(self, result: dict) -> Optional[Alert]:
        try:
            if result["is_dga"]:
                confidence = result["confidence"]
                return self._dict_to_alert({
                    "threat_class": "dga",
                    "severity": "high" if confidence > 0.6 else "medium",
                    "confidence": confidence,
                    "evidence": [
                        Evidence(
                            feature_name="domain_entropy",
                            value=round(result["features"]["domain_entropy"], 3),
                            contribution=0.3,
                            description=f"Domain entropy: {result['features']['domain_entropy']:.3f}"
                        ),
                        Evidence(
                            feature_name="bigram_log_likelihood_3",
                            value=round(result["features"]["bigram_log_likelihood_3"], 4),
                            contribution=0.25,
                            description=f"Bigram log-likelihood: {result['features']['bigram_log_likelihood_3']:.4f}"
                        ),
                        Evidence(
                            feature_name="digit_ratio",
                            value=round(result["features"]["digit_ratio"], 3),
                            contribution=0.2,
                            description=f"Digit ratio: {result['features']['digit_ratio']:.3f}"
                        ),
                        Evidence(
                            feature_name="consonant_vowel_ratio",
                            value=round(result["features"]["consonant_vowel_ratio"], 3),
                            contribution=0.15,
                            description=f"Consonant-vowel ratio: {result['features']['consonant_vowel_ratio']:.3f}"
                        ),
                    ],
                    "model_version": "lightgbm_dga_v1",
                })
            return None
        except Exception as e:
            logger.error(f"DGA detection error: {e}")
            return None

    @staticmethod
    def _dict_to_alert(detection: dict) -> Optional[Alert]:
        """Convert detection dict to Alert Pydantic model."""
        try:
            # Map threat_class to severity
            severity_map = {
                "ddos": "high" if detection.get("confidence", 0) > 0.6 else "medium",
                "c2_beacon": "high" if detection.get("confidence", 0) > 0.5 else "medium",
                "dga": "high" if detection.get("confidence", 0) > 0.6 else "medium",
                "tls_malware": "high" if detection.get("confidence", 0) > 0.7 else "medium",
                "port_scan": "medium" if detection.get("confidence", 0) > 0.5 else "low",
                "exfiltration": "high" if detection.get("confidence", 0) > 0.5 else "medium",
            }

            threat_class = detection.get("threat_class", "unknown")
            severity = severity_map.get(threat_class, "low")
            confidence = detection.get("confidence", 0.0)

            # Build Evidence list
            evidence_list = detection.get("evidence", [])
            # Ensure evidence is list of Evidence objects
            from app.alerts.schema import Evidence
            evidence_objects = []
            for e in evidence_list:
                if isinstance(e, Evidence):
                    evidence_objects.append(e)
                elif isinstance(e, dict):
                    evidence_objects.append(Evidence(**e))

            # flow_id: kept human-readable with a millisecond timestamp is fine —
            # collisions here just mean two alerts share a display label, not
            # data loss. alert_id below is different: AlertManager uses it as a
            # dict key, so a collision there silently overwrites one alert with
            # another. flow_id can stay as-is.
            flow_id = detection.get("flow_id") or f"flow_{int(time.time() * 1000)}"

            alert = Alert(
                # uuid4, not a millisecond timestamp: AlertManager stores alerts
                # keyed by alert_id (`self._active_alerts[alert.alert_id] = alert`).
                # A timestamp-based id has no uniqueness guarantee once more than
                # one alert can be constructed within the same millisecond — which
                # is common once inference is batched, and was silently dropping
                # alerts (verified: 82 dispatched alerts collapsed to 39 unique
                # ids, one id overwritten 7 times) even though detection itself
                # was correct. uuid4 makes collisions astronomically unlikely
                # regardless of how fast alerts are produced.
                alert_id=detection.get("alert_id") or f"threat_{uuid.uuid4().hex[:12]}",
                flow_id=flow_id,
                threat_class=threat_class,
                severity=severity,
                confidence=confidence,
                source_ip=detection.get("source_ip", "0.0.0.0"),
                destination_ip=detection.get("destination_ip", "0.0.0.0"),
                source_port=detection.get("source_port"),
                destination_port=detection.get("destination_port"),
                protocol=detection.get("protocol", "tcp"),
                bytes_transferred=detection.get("bytes_transferred", 0),
                packet_count=detection.get("packet_count", 0),
                duration_seconds=detection.get("duration_seconds", 0.0),
                evidence=evidence_objects,
                model_version=detection.get("model_version", "unknown"),
                raw_features=detection.get("raw_features", {}),
            )
            return alert
        except Exception as e:
            logger.error(f"Error converting detection to alert: {e}")
            return None

    @staticmethod
    def _tls_result_to_alert(result: dict, flow: Any) -> Optional[Alert]:
        """Convert TLS detector result to Alert."""
        try:
            from app.alerts.schema import Evidence

            severity = "high" if result.get("confidence", 0) > 0.7 else "medium"

            # Get top feature evidences
            evidence_list = result.get("evidence", [])
            evidence_objects = []
            if isinstance(evidence_list, list):
                for e in evidence_list[:5]:  # Top 5
                    if isinstance(e, Evidence):
                        evidence_objects.append(e)
                    elif isinstance(e, dict):
                        evidence_objects.append(Evidence(**e))

            dur = getattr(flow, 'duration_seconds', 0.0)
            if callable(dur):
                try: dur = dur()
                except Exception: dur = 0.0
            return Alert(
                alert_id=f"tls_malware_{uuid.uuid4().hex[:12]}",
                flow_id=getattr(flow, 'key', f"flow_{int(time.time()*1000)}"),
                threat_class="tls_malware",
                severity=severity,
                confidence=result.get("confidence", 0.0),
                source_ip=getattr(flow, 'src_ip', '0.0.0.0'),
                destination_ip=getattr(flow, 'dst_ip', '0.0.0.0'),
                source_port=getattr(flow, 'src_port', None),
                destination_port=getattr(flow, 'dst_port', None),
                protocol=getattr(flow, 'protocol', 'tcp'),
                bytes_transferred=getattr(flow, 'bytes_transferred', 0),
                packet_count=getattr(flow, 'packet_count', 0),
                duration_seconds=float(dur),
                evidence=evidence_objects,
                model_version=result.get("model_version", "random_forest_ja3_v1"),
                raw_features=getattr(flow, 'raw_features', {}),
            )
        except Exception as e:
            logger.error(f"TLS result to alert conversion error: {e}")
            return None

    @staticmethod
    def _scan_result_to_alert(result: dict, flow: Any) -> Optional[Alert]:
        """Convert scan detector result to Alert."""
        try:
            from app.alerts.schema import Evidence

            severity = result.get("severity", "medium")
            confidence = result.get("confidence", 0.0)

            evidence_list = result.get("evidence", [])
            evidence_objects = []
            if isinstance(evidence_list, list):
                for e in evidence_list:
                    if isinstance(e, Evidence):
                        evidence_objects.append(e)
                    elif isinstance(e, dict):
                        evidence_objects.append(Evidence(**e))

            dur2 = getattr(flow, 'duration_seconds', 0.0)
            if callable(dur2):
                try: dur2 = dur2()
                except Exception: dur2 = 0.0
            return Alert(
                alert_id=f"port_scan_{uuid.uuid4().hex[:12]}",
                flow_id=getattr(flow, 'key', f"flow_{int(time.time()*1000)}"),
                threat_class="port_scan",
                severity=severity,
                confidence=confidence,
                source_ip=getattr(flow, 'src_ip', '0.0.0.0'),
                destination_ip=getattr(flow, 'dst_ip', '0.0.0.0'),
                source_port=getattr(flow, 'src_port', None),
                destination_port=getattr(flow, 'dst_port', None),
                protocol=getattr(flow, 'protocol', 'tcp'),
                bytes_transferred=getattr(flow, 'bytes_transferred', 0),
                packet_count=getattr(flow, 'packet_count', 0),
                duration_seconds=float(dur2),
                evidence=evidence_objects,
                model_version=result.get("model_version", "statistical_scan_detector_v1"),
                raw_features=getattr(flow, 'raw_features', {}),
            )
        except Exception as e:
            logger.error(f"Scan result to alert conversion error: {e}")
            return None

    @staticmethod
    def _finalize_alert(alert: Alert):
        """Finalize alert: ensure confidence is bounded, severity assigned correctly."""
        # Ensure confidence is in [0, 1]
        alert.confidence = max(0.0, min(1.0, alert.confidence))

        # Ensure severity is set
        if not alert.severity:
            alert.severity = "low"

        # Boost severity based on confidence
        if alert.confidence >= 0.8:
            if alert.severity in ("low", "medium"):
                alert.severity = "high"
        elif alert.confidence >= 0.6:
            if alert.severity in ("low",):
                alert.severity = "medium"

    @staticmethod
    def _deduplicate_alerts(alerts: List[Alert]) -> List[Alert]:
        """Remove duplicate alerts (same threat_class + source/dest)."""

        seen_keys = set()
        deduped = []

        for alert in alerts:
            # Create a dedup key from threat class + normalized source/dest
            key = (
                alert.threat_class,
                alert.source_ip.lower(),
                alert.destination_ip.lower(),
                alert.protocol,
            )

            if key not in seen_keys:
                seen_keys.add(key)
                deduped.append(alert)
            else:
                # Merge with existing: take max confidence
                for existing in deduped:
                    if (existing.threat_class, existing.source_ip.lower(),
                        existing.destination_ip.lower(), existing.protocol) == key:
                        if alert.confidence > existing.confidence:
                            existing.confidence = alert.confidence
                            # Add evidence if new evidence provides different features
                            for new_e in alert.evidence:
                                existing_e_names = {e.feature_name for e in existing.evidence}
                                if new_e.feature_name not in existing_e_names:
                                    existing.evidence.append(new_e)
                        break

        return deduped