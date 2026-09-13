from __future__ import annotations

import asyncio
import json
import time
import logging
from typing import Dict, List, Any, Optional, Tuple

import numpy as np

from app.config import settings
from app.alerts.schema import Alert, Evidence
from app.models.ddos_detector import DDOSDetector, get_ddos_detector
from app.models.beacon_detector import BeaconDetector
from app.models.dga_classifier import predict_dga, train_dga_model, load_alexa_top_1m, load_dgarchive_samples
from app.models.tls_classifier import TLSMalwareClassifier, get_tls_malware_classifier
from app.models.scan_detector import ScanDetector, get_scan_detector
from app.models.exfil_detector import ExfiltrationDetector
from app.models.dns_tunnel_detector import DnsTunnelDetector

logger = logging.getLogger(__name__)


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
        }
        self._model_loaded: Dict[str, bool] = {
            "dga": False,
        }
        self._lock = asyncio.Lock()

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

    async def analyze_flow(self, flow: Any) -> List[Alert]:
        """Analyze a flow through all 6 detectors in parallel.

        Args:
            flow: FlowState object with accumulated packet metadata

        Returns:
            List of detected alerts (may be empty if no threats found)
        """
        async with self._lock:
            # Run all detectors concurrently
            # Each detector returns Optional[Alert] or Optional[dict]
            tasks = [
                self._run_detector("ddos", flow),
                self._run_detector("beacon", flow),
                self._run_detector("dga", flow),
                self._run_detector("tls", flow),
                self._run_detector("scan", flow),
                self._run_detector("exfil", flow),
                self._run_detector("dns_tunnel", flow),
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
                all_flows = self._get_all_flows_from_src(flow)
                flow_dict = flow.to_dict() if hasattr(flow, 'to_dict') else (dict(flow) if isinstance(flow, dict) else getattr(flow, '__dict__', {}))
                result = detector.detect(flow_dict, all_flows_from_src=all_flows)
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

            result = predict_dga(model, domain)
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
                if flow is not None:
                    pass  # _enrich_detection placeholder removed; dict already complete
            return None
        except Exception as e:
            logger.error(f"DGA detection error: {e}")
            return None

    def _get_all_flows_from_src(self, flow: Any) -> dict:
        """Get all flows from the same source IP.

        In a real implementation, this would query the flow table.
        For MVP, returns empty dict.
        """
        # Placeholder - in production, query flow_table
        return {}

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

            flow_id = detection.get("flow_id") or f"flow_{int(time.time() * 1000)}"

            alert = Alert(
                alert_id=detection.get("alert_id", f"threat_{int(time.time() * 1000)}"),
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
                alert_id=f"tls_malware_{int(time.time() * 1000)}",
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
                alert_id=f"port_scan_{int(time.time() * 1000)}",
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