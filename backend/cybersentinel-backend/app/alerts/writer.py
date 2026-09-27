"""Batched, non-blocking alert persistence.

Previously every new alert opened a fresh SQLite connection, INSERTed one row,
committed and closed - synchronously on the asyncio event loop. Under an alert
burst that stalls ingest on disk I/O. This writer owns ONE connection in a
background thread (WAL journal) and writes rows in batches with executemany.

Semantics are unchanged: every *new* alert is persisted (merged duplicates
update the in-memory alert, as before). Call flush() to block until everything
queued so far is on disk (used by tests and on shutdown).
"""
from __future__ import annotations

import atexit
import json
import logging
import queue
import sqlite3
import threading
import time
from typing import Optional

logger = logging.getLogger(__name__)

_INSERT = (
    "INSERT OR IGNORE INTO alerts (alert_id, timestamp, flow_id, threat_class, severity, "
    "confidence, source_ip, source_port, destination_ip, destination_port, protocol, "
    "bytes_transferred, packet_count, duration_seconds, evidence, model_version, raw_features) "
    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
)


def _row(alert) -> tuple:
    ts = alert.timestamp
    return (
        alert.alert_id,
        ts.isoformat() if hasattr(ts, "isoformat") else str(ts),
        alert.flow_id, alert.threat_class, alert.severity, alert.confidence,
        alert.source_ip, alert.source_port, alert.destination_ip, alert.destination_port,
        alert.protocol, alert.bytes_transferred, alert.packet_count, alert.duration_seconds,
        json.dumps([{"feature_name": e.feature_name, "value": e.value,
                     "contribution": e.contribution, "description": e.description}
                    for e in alert.evidence]),
        alert.model_version,
        json.dumps(alert.raw_features or {}, default=str),
    )


class AlertWriter:
    def __init__(self, max_batch: int = 1000, max_wait_s: float = 0.25):
        self._q: "queue.SimpleQueue" = queue.SimpleQueue()
        self._max_batch = max_batch
        self._max_wait = max_wait_s
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self.written = 0
        self.errors = 0

    def _ensure_started(self):
        if self._thread is None:
            with self._lock:
                if self._thread is None:
                    self._thread = threading.Thread(target=self._run, name="alert-writer", daemon=True)
                    self._thread.start()

    def submit(self, alert) -> None:
        try:
            self._q.put(("row", _row(alert)))
        except Exception as e:  # never let persistence break detection
            self.errors += 1
            logger.debug("alert row build failed: %s", e)
            return
        self._ensure_started()

    def flush(self, timeout: float = 10.0) -> bool:
        """Block until every row submitted before this call is committed."""
        self._ensure_started()
        done = threading.Event()
        self._q.put(("flush", done))
        return done.wait(timeout)

    def _connect(self):
        from app.db import session
        try:
            session.init_db()  # idempotent CREATE TABLE IF NOT EXISTS
        except Exception as e:
            logger.debug("init_db in writer: %s", e)
        conn = sqlite3.connect(session.DB_PATH, check_same_thread=False)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
        except Exception:
            pass
        return conn

    def _run(self):
        conn = None
        while True:
            rows, waiters = [], []
            item = self._q.get()  # block for the first item
            deadline = time.monotonic() + self._max_wait
            while True:
                kind, payload = item
                if kind == "row":
                    rows.append(payload)
                else:
                    waiters.append(payload)
                if len(rows) >= self._max_batch or waiters:
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    item = self._q.get(timeout=remaining)
                except queue.Empty:
                    break
            if rows:
                try:
                    if conn is None:
                        conn = self._connect()
                    conn.executemany(_INSERT, rows)
                    conn.commit()
                    self.written += len(rows)
                except Exception as e:
                    self.errors += 1
                    logger.warning("alert batch persist failed (%d rows): %s", len(rows), e)
                    try:
                        if conn is not None:
                            conn.close()
                    except Exception:
                        pass
                    conn = None
            for w in waiters:
                w.set()


_writer: Optional[AlertWriter] = None


def get_alert_writer() -> AlertWriter:
    global _writer
    if _writer is None:
        w = AlertWriter()
        atexit.register(w.flush, 5.0)  # bind the instance, not the global
        _writer = w
    return _writer
