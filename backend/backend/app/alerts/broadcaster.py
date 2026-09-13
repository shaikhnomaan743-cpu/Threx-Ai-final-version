from __future__ import annotations

import asyncio
import logging
from typing import Dict, Set, Any, Optional

from app.alerts.schema import Alert

logger = logging.getLogger(__name__)


class AlertBroadcaster:
    """WebSocket broadcast fan-out for new alerts.

    Maintains connected clients and broadcasts new alerts to all
    subscribed WebSocket connections.
    """

    def __init__(self):
        self._connected: Set[asyncio.Queue] = set()
        self._alert_history: List[Alert] = []
        self._max_history = 100  # Max alerts to broadcast on connect

    def subscribe(self) -> asyncio.Queue:
        """Subscribe to alert broadcasts. Returns a queue to read from."""
        queue = asyncio.Queue()
        self._connected.add(queue)
        logger.debug(f"WebSocket subscriber connected. Total: {len(self._connected)}")

        # Send recent history on connect
        asyncio.create_task(self._send_history(queue))

        return queue

    async def unsubscribe(self, queue: asyncio.Queue):
        """Unsubscribe a WebSocket client."""
        self._connected.discard(queue)
        await queue.put(None)  # Stop reading
        logger.debug(f"WebSocket subscriber disconnected. Total: {len(self._connected)}")

    async def broadcast(self, alert: Alert):
        """Broadcast a new alert to all connected WebSocket clients.

        Args:
            alert: Alert Pydantic model to broadcast
        """
        if not self._connected:
            return

        # Prepare broadcast data (serialize alert to dict)
        alert_dict = {
            "alert_id": alert.alert_id,
            "timestamp": alert.timestamp.isoformat(),
            "threat_class": alert.threat_class,
            "severity": alert.severity,
            "confidence": alert.confidence,
            "source_ip": alert.source_ip,
            "destination_ip": alert.destination_ip,
            "source_port": alert.source_port,
            "destination_port": alert.destination_port,
            "protocol": alert.protocol,
            "bytes_transferred": alert.bytes_transferred,
            "packet_count": alert.packet_count,
            "duration_seconds": alert.duration_seconds,
            "evidence": [
                {
                    "feature_name": e.feature_name,
                    "value": e.value,
                    "contribution": e.contribution,
                    "description": e.description,
                }
                for e in alert.evidence
            ],
            "model_version": alert.model_version,
            "raw_features": alert.raw_features,
        }

        # Send to all connected clients
        disconnected = set()
        for queue in self._connected:
            try:
                await queue.put(alert_dict)
            except (RuntimeError, Exception):
                # Queue full or closed
                disconnected.add(queue)

        # Remove disconnected
        self._connected.difference_update(disconnected)

        # Add to history
        self._alert_history.append(alert)
        if len(self._alert_history) > self._max_history:
            self._alert_history = self._alert_history[-self._max_history:]

    async def broadcast_history(self, queue: asyncio.Queue):
        """Send alert history to a newly connected client."""
        for alert in self._alert_history[-self._max_history:]:
            try:
                alert_dict = {
                    "alert_id": alert.alert_id,
                    "timestamp": alert.timestamp.isoformat(),
                    "threat_class": alert.threat_class,
                    "severity": alert.severity,
                    "confidence": alert.confidence,
                    "source_ip": alert.source_ip,
                    "destination_ip": alert.destination_ip,
                    "source_port": alert.source_port,
                    "destination_port": alert.destination_port,
                    "protocol": alert.protocol,
                    "bytes_transferred": alert.bytes_transferred,
                    "packet_count": alert.packet_count,
                    "duration_seconds": alert.duration_seconds,
                    "evidence": [
                        {
                            "feature_name": e.feature_name,
                            "value": e.value,
                            "contribution": e.contribution,
                            "description": e.description,
                        }
                        for e in alert.evidence
                    ],
                    "model_version": alert.model_version,
                    "raw_features": alert.raw_features,
                }
                await queue.put(alert_dict)
            except Exception:
                break

    async def _send_history(self, queue: asyncio.Queue):
        """Send recent alert history to a subscriber."""
        try:
            for alert in self._alert_history[-self._max_history:]:
                await asyncio.sleep(0.01)  # Small delay between sends
                try:
                    alert_dict = {
                        "alert_id": alert.alert_id,
                        "timestamp": alert.timestamp.isoformat(),
                        "threat_class": alert.threat_class,
                        "severity": alert.severity,
                        "confidence": alert.confidence,
                        "source_ip": alert.source_ip,
                        "destination_ip": alert.destination_ip,
                        "source_port": alert.source_port,
                        "destination_port": alert.destination_port,
                        "protocol": alert.protocol,
                        "bytes_transferred": alert.bytes_transferred,
                        "packet_count": alert.packet_count,
                        "duration_seconds": alert.duration_seconds,
                        "evidence": [
                            {
                                "feature_name": e.feature_name,
                                "value": e.value,
                                "contribution": e.contribution,
                                "description": e.description,
                            }
                            for e in alert.evidence
                        ],
                        "model_version": alert.model_version,
                        "raw_features": alert.raw_features,
                    }
                    await queue.put(alert_dict)
                except Exception:
                    break
        except Exception:
            pass

    def get_connection_count(self) -> int:
        """Get number of connected WebSocket clients."""
        return len(self._connected)

    def get_recent_alerts(self, limit: int = 50) -> List[dict]:
        """Get recent alerts as dicts for API responses."""
        recent = self._alert_history[-limit:]
        return [
            {
                "alert_id": a.alert_id,
                "timestamp": a.timestamp.isoformat(),
                "threat_class": a.threat_class,
                "severity": a.severity,
                "confidence": a.confidence,
                "source_ip": a.source_ip,
                "destination_ip": a.destination_ip,
            }
            for a in recent
        ]