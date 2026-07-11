"""
SQLite Persistence Layer
-------------------------
Thread-safe database for storing incidents, firewall actions,
visitors, and device profiles. All data survives restarts.

Tables:
  incidents      — every security alert with risk score and action
  firewall_log   — every block/unblock action with reason
  visitors       — HTTP visitors tracked by IP
  devices        — device profiles for tracked IPs
"""

import os
import sqlite3
import threading
import time
import logging
from typing import Any

_log = logging.getLogger(__name__)

# Module-level singleton
_db_path: str = ""
_lock = threading.Lock()
_initialized = False


# ══════════════════════════════════════════════════════════════════
#  INITIALISATION
# ══════════════════════════════════════════════════════════════════

def init_db(db_path: str) -> None:
    """Create the database and tables if they don't exist."""
    global _db_path, _initialized
    _db_path = db_path

    # Ensure parent directory exists
    db_dir = os.path.dirname(db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    conn = _connect()
    try:
        cur = conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT    NOT NULL DEFAULT (datetime('now')),
                source_ip   TEXT    NOT NULL,
                alert_type  TEXT    NOT NULL,
                severity    TEXT    NOT NULL,
                risk_score  REAL    NOT NULL DEFAULT 0,
                detail      TEXT    NOT NULL DEFAULT '',
                action      TEXT    NOT NULL DEFAULT 'none',
                status      TEXT    NOT NULL DEFAULT 'active'
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS firewall_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT    NOT NULL DEFAULT (datetime('now')),
                action      TEXT    NOT NULL,
                ip          TEXT    NOT NULL,
                reason      TEXT    NOT NULL DEFAULT '',
                is_auto     INTEGER NOT NULL DEFAULT 0
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS visitors (
                ip              TEXT PRIMARY KEY,
                user_agent      TEXT    NOT NULL DEFAULT '',
                request_count   INTEGER NOT NULL DEFAULT 1,
                first_seen      TEXT    NOT NULL DEFAULT (datetime('now')),
                last_seen       TEXT    NOT NULL DEFAULT (datetime('now')),
                last_page       TEXT    NOT NULL DEFAULT '/',
                risk_score      REAL    NOT NULL DEFAULT 0,
                is_blocked      INTEGER NOT NULL DEFAULT 0
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                ip              TEXT PRIMARY KEY,
                hostname        TEXT    NOT NULL DEFAULT '',
                mac_address     TEXT    NOT NULL DEFAULT '',
                device_name     TEXT    NOT NULL DEFAULT '',
                device_type     TEXT    NOT NULL DEFAULT 'Unknown',
                status          TEXT    NOT NULL DEFAULT 'active',
                risk_score      REAL    NOT NULL DEFAULT 0,
                last_activity   TEXT    NOT NULL DEFAULT (datetime('now')),
                reason          TEXT    NOT NULL DEFAULT ''
            )
        """)

        # Indexes for common queries
        cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_ip ON incidents(source_ip)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_time ON incidents(timestamp)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_firewall_ip ON firewall_log(ip)")

        conn.commit()
        _initialized = True
        _log.info("Database initialised: %s", db_path)
    finally:
        conn.close()


def _connect() -> sqlite3.Connection:
    """Open a thread-local connection with WAL mode."""
    conn = sqlite3.connect(_db_path, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def _execute(sql: str, params: tuple = ()) -> list[dict]:
    """Execute a query and return results as list of dicts."""
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute(sql, params)
            if sql.strip().upper().startswith("SELECT"):
                rows = cur.fetchall()
                return [dict(row) for row in rows]
            conn.commit()
            return []
        except Exception as exc:
            _log.error("Database error: %s — SQL: %s", exc, sql[:120])
            return []
        finally:
            conn.close()


# ══════════════════════════════════════════════════════════════════
#  INCIDENTS
# ══════════════════════════════════════════════════════════════════

def log_incident(
    source_ip: str,
    alert_type: str,
    severity: str,
    risk_score: float,
    detail: str = "",
    action: str = "none",
) -> None:
    """Record a security incident."""
    _execute(
        "INSERT INTO incidents (source_ip, alert_type, severity, risk_score, detail, action) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (source_ip, alert_type, severity, risk_score, detail, action),
    )


def get_incidents(limit: int = 100, offset: int = 0) -> list[dict]:
    """Return recent incidents, newest first."""
    return _execute(
        "SELECT * FROM incidents ORDER BY id DESC LIMIT ? OFFSET ?",
        (limit, offset),
    )


def get_incident_stats() -> dict:
    """Return aggregate incident counts."""
    rows = _execute(
        "SELECT severity, COUNT(*) as count FROM incidents GROUP BY severity"
    )
    result = {"total": 0, "CRITICAL": 0, "MEDIUM": 0, "LOW": 0}
    for row in rows:
        result[row["severity"]] = row["count"]
        result["total"] += row["count"]
    return result


def get_incident_timeline(hours: int = 24) -> list[dict]:
    """Return incident counts grouped by hour for the last N hours."""
    return _execute(
        "SELECT strftime('%%Y-%%m-%%d %%H:00', timestamp) as hour, "
        "severity, COUNT(*) as count "
        "FROM incidents "
        "WHERE timestamp >= datetime('now', ? || ' hours') "
        "GROUP BY hour, severity "
        "ORDER BY hour ASC",
        (str(-hours),),
    )


def get_top_attackers(limit: int = 10) -> list[dict]:
    """Return top source IPs by total incident risk score."""
    return _execute(
        "SELECT source_ip, "
        "COUNT(*) as incident_count, "
        "SUM(risk_score) as total_score, "
        "MAX(severity) as max_severity, "
        "MAX(timestamp) as last_seen "
        "FROM incidents "
        "WHERE source_ip NOT IN ('-', 'outbound', '127.0.0.1', '0.0.0.0') "
        "GROUP BY source_ip "
        "ORDER BY total_score DESC "
        "LIMIT ?",
        (limit,),
    )


# ══════════════════════════════════════════════════════════════════
#  FIREWALL LOG
# ══════════════════════════════════════════════════════════════════

def log_firewall_action(
    action: str, ip: str, reason: str = "", is_auto: bool = False
) -> None:
    """Record a firewall block or unblock action."""
    _execute(
        "INSERT INTO firewall_log (action, ip, reason, is_auto) VALUES (?, ?, ?, ?)",
        (action, ip, reason, 1 if is_auto else 0),
    )


def get_firewall_log(limit: int = 50) -> list[dict]:
    """Return recent firewall actions."""
    return _execute(
        "SELECT * FROM firewall_log ORDER BY id DESC LIMIT ?",
        (limit,),
    )


# ══════════════════════════════════════════════════════════════════
#  VISITORS
# ══════════════════════════════════════════════════════════════════

def upsert_visitor(
    ip: str, user_agent: str = "", page: str = "/", risk_score: float = 0.0,
    is_blocked: bool = False,
) -> None:
    """Insert or update a visitor record."""
    _execute(
        "INSERT INTO visitors (ip, user_agent, request_count, first_seen, last_seen, last_page, risk_score, is_blocked) "
        "VALUES (?, ?, 1, datetime('now'), datetime('now'), ?, ?, ?) "
        "ON CONFLICT(ip) DO UPDATE SET "
        "user_agent = excluded.user_agent, "
        "request_count = request_count + 1, "
        "last_seen = datetime('now'), "
        "last_page = excluded.last_page, "
        "risk_score = excluded.risk_score, "
        "is_blocked = excluded.is_blocked",
        (ip, user_agent, page, risk_score, 1 if is_blocked else 0),
    )


def get_visitors() -> list[dict]:
    """Return all tracked visitors."""
    return _execute("SELECT * FROM visitors ORDER BY last_seen DESC")


# ══════════════════════════════════════════════════════════════════
#  DEVICES
# ══════════════════════════════════════════════════════════════════

def upsert_device(
    ip: str,
    hostname: str = "",
    mac_address: str = "",
    device_name: str = "",
    device_type: str = "Unknown",
    status: str = "active",
    risk_score: float = 0.0,
    reason: str = "",
) -> None:
    """Insert or update a device profile."""
    _execute(
        "INSERT INTO devices (ip, hostname, mac_address, device_name, device_type, status, risk_score, last_activity, reason) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), ?) "
        "ON CONFLICT(ip) DO UPDATE SET "
        "hostname = CASE WHEN excluded.hostname != '' THEN excluded.hostname ELSE hostname END, "
        "mac_address = CASE WHEN excluded.mac_address != '' THEN excluded.mac_address ELSE mac_address END, "
        "device_name = CASE WHEN excluded.device_name != '' THEN excluded.device_name ELSE device_name END, "
        "device_type = excluded.device_type, "
        "status = excluded.status, "
        "risk_score = excluded.risk_score, "
        "last_activity = datetime('now'), "
        "reason = excluded.reason",
        (ip, hostname, mac_address, device_name, device_type, status, risk_score, reason),
    )


def get_devices() -> list[dict]:
    """Return all tracked devices."""
    return _execute("SELECT * FROM devices ORDER BY last_activity DESC")


# ══════════════════════════════════════════════════════════════════
#  HEALTH
# ══════════════════════════════════════════════════════════════════

def is_healthy() -> bool:
    """Return True if the database is accessible."""
    try:
        rows = _execute("SELECT 1")
        return len(rows) > 0
    except Exception:
        return False
