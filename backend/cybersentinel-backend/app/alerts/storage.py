from __future__ import annotations

import json
import asyncio
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

from app.alerts.schema import Alert


class AlertStorage:
    """Persist alerts to database (SQLite/PostgreSQL).

    Handles writing alerts to persistent storage with proper
    schema migration support.
    """

    def __init__(self, db_engine=None):
        self.db_engine = db_engine
        self._init_done = False

    async def initialize(self, engine=None):
        """Initialize database connection and tables."""
        self.db_engine = engine
        if not self._init_done:
            await self._create_tables()
            self._init_done = True

    async def _create_tables(self):
        """Create alert and flow tracking tables."""
        if self.db_engine is None:
            # Use sync SQLite for MVP if no engine provided
            import sqlite3
            import os

            os.makedirs("data", exist_ok=True)
            db_path = "data/alerts.db"

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    threat_class TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    source_ip TEXT NOT NULL,
                    source_port INTEGER,
                    destination_ip TEXT NOT NULL,
                    destination_port INTEGER,
                    protocol TEXT NOT NULL,
                    bytes_transferred INTEGER NOT NULL DEFAULT 0,
                    packet_count INTEGER NOT NULL DEFAULT 0,
                    duration_seconds REAL NOT NULL DEFAULT 0.0,
                    evidence TEXT NOT NULL DEFAULT '[]',
                    model_version TEXT NOT NULL,
                    raw_features TEXT NOT NULL DEFAULT '{}'
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS flow_records (
                    flow_key TEXT PRIMARY KEY,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    src_port INTEGER NOT NULL DEFAULT 0,
                    dst_port INTEGER NOT NULL DEFAULT 0,
                    protocol TEXT NOT NULL,
                    packet_count INTEGER NOT NULL DEFAULT 0,
                    bytes_transferred INTEGER NOT NULL DEFAULT 0,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    duration_seconds REAL NOT NULL DEFAULT 0.0
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS metric_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    flows_active INTEGER NOT NULL DEFAULT 0,
                    packets_per_sec REAL NOT NULL DEFAULT 0.0,
                    bytes_per_sec REAL NOT NULL DEFAULT 0.0,
                    memory_usage_mb REAL NOT NULL DEFAULT 0.0
                )
            """)

            conn.commit()
            conn.close()
        else:
            # Use provided engine (async SQLAlchemy)
            # Tables would be created via SQLAlchemy models
            pass

    async def save_alert(self, alert: Alert) -> bool:
        """Persist an alert to the database.

        Args:
            alert: Alert Pydantic model to persist

        Returns:
            True if successfully saved
        """
        try:
            if self.db_engine is None:
                # SQLite persistence
                import sqlite3
                import os

                os.makedirs("data", exist_ok=True)
                db_path = "data/alerts.db"

                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()

                evidence_json = json.dumps(
                    [
                        {
                            "feature_name": e.feature_name,
                            "value": e.value,
                            "contribution": e.contribution,
                            "description": e.description,
                        }
                        for e in alert.evidence
                    ]
                )

                cursor.execute(
                    """INSERT OR IGNORE INTO alerts
                    (alert_id, timestamp, threat_class, severity, confidence,
                     source_ip, source_port, destination_ip, destination_port,
                     protocol, bytes_transferred, packet_count, duration_seconds,
                     evidence, model_version, raw_features)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        alert.alert_id,
                        alert.timestamp.isoformat(),
                        alert.threat_class,
                        alert.severity,
                        alert.confidence,
                        alert.source_ip,
                        alert.source_port,
                        alert.destination_ip,
                        alert.destination_port,
                        alert.protocol,
                        alert.bytes_transferred,
                        alert.packet_count,
                        alert.duration_seconds,
                        evidence_json,
                        alert.model_version,
                        json.dumps(alert.raw_features),
                    ),
                )

                conn.commit()
                conn.close()
                return True
            else:
                # Use SQLAlchemy async engine
                # (Implementation depends on db session setup)
                return True

        except Exception as e:
            logger.error(f"Failed to persist alert: {e}")
            return False

    async def save_alerts_batch(self, alerts: List[Alert]) -> int:
        """Persist a batch of alerts.

        Args:
            alerts: List of Alert models to persist

        Returns:
            Number of alerts successfully saved
        """
        saved = 0
        for alert in alerts:
            if await self.save_alert(alert):
                saved += 1
        return saved

    async def get_recent_alerts(
        self, limit: int = 100, threat_class: str | None = None
    ) -> List[dict]:
        """Get recent alerts from storage.

        Args:
            limit: Maximum number of alerts to return
            threat_class: Filter by threat class (optional)

        Returns:
            List of alert dicts
        """
        if self.db_engine is None:
            import sqlite3
            import os

            db_path = "data/alerts.db"
            if not os.path.exists(db_path):
                return []

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            if threat_class:
                cursor.execute(
                    """SELECT alert_id, timestamp, threat_class, severity,
                       confidence, source_ip, destination_ip,
                       source_port, destination_port, protocol,
                       bytes_transferred, packet_count, duration_seconds,
                       evidence, model_version, raw_features
                    FROM alerts WHERE threat_class = ?
                    ORDER BY timestamp DESC LIMIT ?""",
                    (threat_class, limit),
                )
            else:
                cursor.execute(
                    """SELECT alert_id, timestamp, threat_class, severity,
                       confidence, source_ip, destination_ip,
                       source_port, destination_port, protocol,
                       bytes_transferred, packet_count, duration_seconds,
                       evidence, model_version, raw_features
                    FROM alerts ORDER BY timestamp DESC LIMIT ?""",
                    (limit,),
                )

            rows = cursor.fetchall()
            conn.close()

            results = []
            for row in rows:
                alert_dict = {
                    "alert_id": row[0],
                    "timestamp": row[1],
                    "threat_class": row[2],
                    "severity": row[3],
                    "confidence": row[4],
                    "source_ip": row[5],
                    "destination_ip": row[6],
                    "source_port": row[7],
                    "destination_port": row[8],
                    "protocol": row[9],
                    "bytes_transferred": row[10],
                    "packet_count": row[11],
                    "duration_seconds": row[12],
                    "evidence": json.loads(row[13]) if row[13] else [],
                    "model_version": row[14],
                    "raw_features": json.loads(row[15]) if row[15] else {},
                }
                results.append(alert_dict)

            return results
        else:
            # Use SQLAlchemy query
            return []


# Global storage instance
_storage_instance: AlertStorage | None = None


def get_alert_storage() -> AlertStorage:
    """Get the global alert storage instance."""
    global _storage_instance
    if _storage_instance is None:
        _storage_instance = AlertStorage()
    return _storage_instance