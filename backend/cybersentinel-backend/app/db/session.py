import sqlite3
import os
import logging

logger = logging.getLogger(__name__)

try:
    from app.config import settings as _settings
    _DEFAULT_DB = _settings.db_path
except Exception:
    _DEFAULT_DB = "data/alerts.db"
DB_PATH = os.environ.get("CYBERSENTINEL_DB_PATH", _DEFAULT_DB)


def get_db():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            flow_id TEXT NOT NULL,
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
        CREATE TABLE IF NOT EXISTS analyst_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT NOT NULL,
            note TEXT NOT NULL,
            analyst TEXT NOT NULL DEFAULT 'Analyst',
            created_at TEXT NOT NULL,
            FOREIGN KEY (alert_id) REFERENCES alerts(alert_id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alert_statuses (
            alert_id TEXT PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'new',
            updated_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()
    logger.info(f"Database initialized at {DB_PATH}")


async def init_db_session():
    init_db()

async def close_db_session():
    pass
