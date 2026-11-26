"""SQLite storage for the zero-knowledge link service.

One table carries links: ``links``. The server stores an opaque ciphertext
blob and a counter. It never stores a destination URL, a note, a password, a
key, an IP, a user agent or a referrer.

Everything else is the operator console's session and the abuse reports. There
is no account table: the service has no users, only links.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
-- The zero-knowledge link table. Every column is either an opaque blob or a
-- number the server must know to enforce the budget.
CREATE TABLE IF NOT EXISTS links (
    id            TEXT PRIMARY KEY,              -- 128-bit base64url, server-chosen
    ciphertext    BLOB,                          -- NULL once spent or expired
    iv            BLOB,                          -- 96-bit AES-GCM nonce
    salt          BLOB,                          -- password KDF salt, NULL if none
    kdf           TEXT NOT NULL DEFAULT 'none',  -- none | pbkdf2-sha256-600k
    max_uses      INTEGER,                       -- NULL = unlimited
    uses          INTEGER NOT NULL DEFAULT 0,
    expires_at    TEXT,
    not_before    TEXT,
    created_at    TEXT NOT NULL,                 -- rounded to the hour
    redirect_mode TEXT NOT NULL DEFAULT 'auto',  -- auto | manual
    has_note      INTEGER NOT NULL DEFAULT 0,    -- a note exists inside the blob
    manage_hash   TEXT,                          -- sha256 of the manage token
    disabled_at   TEXT,
    spent_at      TEXT,                          -- content wiped at this time
    reported      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS links_live ON links(spent_at, expires_at);

-- A report can carry the destination only because the reporter chose to paste
-- it. It is never derived from the link.
CREATE TABLE IF NOT EXISTS reports (
    id         INTEGER PRIMARY KEY,
    link_id    TEXT NOT NULL,
    reason     TEXT NOT NULL DEFAULT '',
    url        TEXT,
    created_at TEXT NOT NULL,
    resolved   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS reports_open ON reports(resolved, id DESC);
"""

# Tables from earlier designs. Dropped on sight, never recreated.
RETIRED = ("sessions", "verify_tokens", "login_attempts", "accounts",
           "legacy_links", "opens", "visitors", "share_tokens", "alerts")


def connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


def _tables(conn: sqlite3.Connection) -> set[str]:
    return {r["name"] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}


def migrate(conn: sqlite3.Connection) -> list[str]:
    """Bring any older database to the current schema. Idempotent."""
    done: list[str] = []
    existing = _tables(conn)

    # A pre-cutover `links` table had a plaintext `target` column. Nothing is
    # carried over: those rows were destroyed or used up before the cutover.
    if "links" in existing:
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(links)")}
        if "target" in cols:
            conn.execute("ALTER TABLE links RENAME TO legacy_links")
            existing = _tables(conn)

    conn.executescript(SCHEMA)

    for table in RETIRED:
        if table in _tables(conn):
            conn.execute(f"DROP TABLE {table}")
            done.append(f"dropped {table}")

    if done:
        conn.execute("VACUUM")
    return done


def init_db(path: Path) -> list[str]:
    conn = connect(path)
    try:
        return migrate(conn)
    finally:
        conn.close()


def db_path(data_dir: Path) -> Path:
    return data_dir / "secret-link.sqlite3"
