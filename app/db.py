"""SQLite storage. One writer at a time, WAL, explicit transactions.

Every mutation that decides whether a link is still usable runs inside
``BEGIN IMMEDIATE`` so two simultaneous opens of a one-time link can never both
succeed (see ``tracking.consume``).
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    id             INTEGER PRIMARY KEY,
    email          TEXT NOT NULL UNIQUE,
    pw_hash        TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    email_verified INTEGER NOT NULL DEFAULT 0,
    default_uses   INTEGER NOT NULL DEFAULT 1,
    notify_email   TEXT,
    alerts         INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    csrf       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS links (
    id           INTEGER PRIMARY KEY,
    account_id   INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    code         TEXT NOT NULL UNIQUE,
    target       TEXT NOT NULL,
    label        TEXT NOT NULL DEFAULT '',
    max_uses     INTEGER,              -- NULL = unlimited
    uses         INTEGER NOT NULL DEFAULT 0,
    mode         TEXT NOT NULL DEFAULT 'destroy',   -- destroy | track
    created_at   TEXT NOT NULL,
    expires_at   TEXT,
    destroyed_at TEXT,
    disabled_at  TEXT
);
CREATE INDEX IF NOT EXISTS links_owner ON links(account_id, id DESC);

CREATE TABLE IF NOT EXISTS visitors (
    id         INTEGER PRIMARY KEY,
    link_id    INTEGER NOT NULL REFERENCES links(id) ON DELETE CASCADE,
    fp         TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    opens      INTEGER NOT NULL DEFAULT 0,
    last_ip    TEXT,
    UNIQUE(link_id, fp)
);

CREATE TABLE IF NOT EXISTS opens (
    id         INTEGER PRIMARY KEY,
    link_id    INTEGER NOT NULL REFERENCES links(id) ON DELETE CASCADE,
    visitor_id INTEGER REFERENCES visitors(id) ON DELETE SET NULL,
    ts         TEXT NOT NULL,
    ip         TEXT,
    ua         TEXT,
    referer    TEXT,
    via        TEXT,
    kind       TEXT NOT NULL DEFAULT 'open'   -- open | preview | share
);
CREATE INDEX IF NOT EXISTS opens_link ON opens(link_id, id DESC);

CREATE TABLE IF NOT EXISTS share_tokens (
    token      TEXT PRIMARY KEY,
    link_id    INTEGER NOT NULL REFERENCES links(id) ON DELETE CASCADE,
    visitor_id INTEGER NOT NULL REFERENCES visitors(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    opens      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS alerts (
    id         INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    link_id    INTEGER REFERENCES links(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL,
    body       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    seen       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS alerts_owner ON alerts(account_id, id DESC);

CREATE TABLE IF NOT EXISTS verify_tokens (
    token      TEXT PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS login_attempts (
    key        TEXT PRIMARY KEY,
    fails      INTEGER NOT NULL DEFAULT 0,
    first_fail TEXT NOT NULL
);
"""


def connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


def init_db(path: Path) -> None:
    conn = connect(path)
    try:
        conn.executescript(SCHEMA)
    finally:
        conn.close()


def db_path(data_dir: Path) -> Path:
    return data_dir / "secret-link.sqlite3"

# Owner decision 2026-11-25: a clicker's address is kept 90 days, then dropped.
IP_RETENTION_DAYS = 90


def purge_ips(conn, days: int = IP_RETENTION_DAYS) -> int:
    """Null out addresses older than the retention window, keep the counts."""
    from datetime import datetime, timedelta, timezone

    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    cur = conn.execute("UPDATE opens SET ip=NULL WHERE ip IS NOT NULL AND ts < ?", (cutoff,))
    conn.execute("UPDATE visitors SET last_ip=NULL WHERE last_ip IS NOT NULL AND first_seen < ?", (cutoff,))
    conn.commit()
    return cur.rowcount
