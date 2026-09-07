from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections import defaultdict
from typing import Dict, List, Optional, Any

from app.alerts.schema import Alert, Evidence
from app.config import settings

logger = logging.getLogger(__name__)


class AlertManager:
    """Manages alert lifecycle: deduplication, aggregation, severity assignment.

    Responsibilities:
    - Deduplicate alerts with same threat_class + source/destination
    - Aggregate multiple alerts into consolidated ones
    - Assign severity based on confidence and threat type
    - Maintain alert history and state
    """

    def __init__(self, max_history: int = 10000):
        self.max_history = max_history
        self._alert_history: List[Alert] = []
        self._active_alerts: Dict[str, Alert] = {}  # alert_id -> Alert
        self._threat_counts: Dict[str, int] = {}  # threat_class -> count
        self._severity_counts: Dict[str, int] = {}  # severity -> count
        self._last_dedup_cleanup = time.time()

    def add_alert(self, alert: Alert) -> Optional[Alert]:
        """Add an alert, applying deduplication and aggregation.

        Returns the consolidated/merged alert or None if duplicate suppressed.
        """
        try:
            # Generate alert ID if not set
            if not alert.alert_id:
                alert.alert_id = str(uuid.uuid4())

            # Create dedup key
            dedup_key = (
                alert.threat_class,
                alert.source_ip.lower(),
                alert.destination_ip.lower(),
                alert.protocol,
            )

            current_time = time.time()

            # Periodic cleanup
            if current_time - self._last_dedup_cleanup > 60:
                self._cleanup_history()
                self._last_dedup_cleanup = current_time

            # Check for existing alert with same dedup key
            existing_id = None
            for aid, existing in self._active_alerts.items():
                existing_key = (
                    existing.threat_class,
                    existing.source_ip.lower(),
                    existing.destination_ip.lower(),
                    existing.protocol,
                )
                if existing_key == dedup_key and (current_time - existing.timestamp.timestamp()) < 300:
                    # Same threat type, same flow, within 5-min window => merge
                    existing_id = aid
                    break

            if existing_id:
                # Merge with existing alert
                existing = self._active_alerts[existing_id]
                alert = self._merge_alerts(existing, alert)
                self._active_alerts[existing_id] = alert

                # Update history
                self._update_history(alert)

                # Update threat counts
                self._update_threat_counts(alert.threat_class, 1)

                logger.info(f"Merged duplicate alert: {existing_id}")
                return alert

            # New alert - add to active
            self._active_alerts[alert.alert_id] = alert
            self._update_history(alert)
            self._update_threat_counts(alert.threat_class, 1)
            # Persist to SQLite (best-effort, sync)
            try:
                from app.db.session import get_db
                import json
                conn = get_db()
                cur = conn.cursor()
                evidence_json = json.dumps([{"feature_name": e.feature_name, "value": e.value, "contribution": e.contribution, "description": e.description} for e in alert.evidence])
                cur.execute("""INSERT OR IGNORE INTO alerts (alert_id, timestamp, flow_id, threat_class, severity, confidence, source_ip, source_port, destination_ip, destination_port, protocol, bytes_transferred, packet_count, duration_seconds, evidence, model_version, raw_features) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (alert.alert_id, alert.timestamp.isoformat() if hasattr(alert.timestamp, 'isoformat') else str(alert.timestamp), alert.flow_id, alert.threat_class, alert.severity, alert.confidence, alert.source_ip, alert.source_port, alert.destination_ip, alert.destination_port, alert.protocol, alert.bytes_transferred, alert.packet_count, alert.duration_seconds, evidence_json, alert.model_version, json.dumps(alert.raw_features or {})))
                conn.commit()
                conn.close()
            except Exception as e:
                logger.debug(f"DB persist skipped: {e}")
            logger.debug(f"New alert added: {alert.alert_id} - {alert.threat_class}")
            return alert

        except Exception as e:
            logger.error(f"Alert manager error: {e}")
            # Return the alert even on error - don't drop it
            if not alert.alert_id:
                alert.alert_id = str(uuid.uuid4())
            return alert

    def _merge_alerts(
        self, existing: Alert, new_alert: Alert
    ) -> Alert:
        """Merge two alerts of the same threat class.

        Takes the higher confidence, combines evidence (avoiding duplicates),
        and updates severity.
        """
        # Take max confidence
        if new_alert.confidence > existing.confidence:
            existing.confidence = new_alert.confidence

        # Combine evidence - avoid duplicate feature names
        existing_e_names = {e.feature_name for e in existing.evidence}
        for new_e in new_alert.evidence:
            if new_e.feature_name not in existing_e_names:
                # Only add if not already present
                similar = any(
                    e.feature_name == new_e.feature_name
                    for e in existing.evidence
                )
                if not similar:
                    existing.evidence.append(new_e)

        # Re-determine severity
        from app.inference.scorer import Scorer
        existing.severity = Scorer.determine_severity(
            existing.confidence, existing.threat_class
        )

        return existing

    def _update_history(self, alert: Alert):
        """Update alert history."""
        self._alert_history.append(alert)
        if len(self._alert_history) > self.max_history:
            self._alert_history = self._alert_history[-self.max_history // 2:]

    def _update_threat_counts(self, threat_class: str, delta: int):
        """Update threat class counts."""
        self._threat_counts[threat_class] = self._threat_counts.get(threat_class, 0) + delta
        if self._threat_counts[threat_class] <= 0:
            self._threat_counts.pop(threat_class, None)

    def _cleanup_history(self):
        """Clean up old alert history."""
        # Remove alerts older than 24 hours from active
        # For MVP, just trim the history list
        cutoff = len(self._alert_history) - self.max_history
        if cutoff > 0:
            self._alert_history = self._alert_history[cutoff:]

    def get_active_alerts(self) -> List[Alert]:
        """Get all currently active (non-deduplicated) alerts."""
        return list(self._active_alerts.values())

    def get_alerts_by_threat(self, threat_class: str) -> List[Alert]:
        """Get all alerts for a specific threat class."""
        return [
            alert for alert in self._active_alerts.values()
            if alert.threat_class == threat_class
        ]

    def get_alerts_by_severity(self, severity: str) -> List[Alert]:
        """Get all alerts with a specific severity."""
        return [
            alert for alert in self._active_alerts.values()
            if alert.severity == severity
        ]

    def load_from_db(self, limit: int = 1000) -> int:
        try:
            from app.db.session import get_db
            import json
            from datetime import datetime
            conn = get_db()
            cur = conn.cursor()
            cur.execute("SELECT alert_id, timestamp, flow_id, threat_class, severity, confidence, source_ip, source_port, destination_ip, destination_port, protocol, bytes_transferred, packet_count, duration_seconds, evidence, model_version, raw_features FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,))
            rows = cur.fetchall()
            conn.close()
            loaded=0
            for r in rows:
                try:
                    ev = json.loads(r[14]) if r[14] else []
                    evidence=[Evidence(feature_name=e.get("feature_name","unknown"), value=e.get("value",0), contribution=e.get("contribution",0), description=e.get("description","")) for e in ev]
                    ts = r[1]
                    from datetime import datetime, timezone
                    try:
                        ts_dt = datetime.fromisoformat(ts.replace("Z","+00:00")) if isinstance(ts,str) else ts
                    except Exception:
                        ts_dt = datetime.now(timezone.utc)
                    alert = Alert(alert_id=r[0], timestamp=ts_dt, flow_id=r[2], threat_class=r[3], severity=r[4], confidence=r[5], source_ip=r[6], source_port=r[7], destination_ip=r[8], destination_port=r[9], protocol=r[10], bytes_transferred=r[11], packet_count=r[12], duration_seconds=r[13], evidence=evidence, model_version=r[15], raw_features=json.loads(r[16]) if r[16] else {})
                    self._active_alerts[alert.alert_id]=alert
                    self._alert_history.append(alert)
                    loaded+=1
                except Exception:
                    continue
            logger.info(f"Loaded {loaded} alerts from persistent DB")
            return loaded
        except Exception as e:
            logger.debug(f"DB load skipped: {e}")
            return 0

    def get_stats(self) -> dict:
        active = self.get_active_alerts()
        return {
            "total_active_alerts": len(active),
            "alerts_by_threat": {
                tc: len(self.get_alerts_by_threat(tc))
                for tc in set(a.threat_class for a in active)
            },
            "alerts_by_severity": {
                sev: len(self.get_alerts_by_severity(sev))
                for sev in ["critical", "high", "medium", "low"]
            },
            "total_history": len(self._alert_history),
        }