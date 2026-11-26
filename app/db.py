"""SQLite storage for the zero-knowledge link service.

Two tables carry links:

* ``links`` — post-cutover, zero-knowledge. The server stores an opaque
  ciphertext blob and a counter. It never stores a destination URL, a note, a
  password, a key, an IP, a user agent or a referrer.
* ``legacy_links`` — links created before the 2026-11-26 cutover. They keep
  resolving until they expire or are destroyed, then the sweeper deletes the
  row (target included). Nothing new is ever written here.

Everything else is account plumbing for the legacy dashboard and the operator
console. No table has a column that can describe a click.
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
    alerts         INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    csrf       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

-- The zero-knowledge link table. Every column is either an opaque blob or a
-- number that the server must know to enforce the budget.
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

-- Pre-cutover links. Target is plaintext because the server has always seen
-- it; there is no honest way to encrypt a URL that was already disclosed.
-- Rows are deleted by the sweeper at expiry or when their budget is spent.
CREATE TABLE IF NOT EXISTS legacy_links (
    id           INTEGER PRIMARY KEY,
    account_id   INTEGER,
    code         TEXT NOT NULL UNIQUE,
    target       TEXT NOT NULL,
    label        TEXT NOT NULL DEFAULT '',
    max_uses     INTEGER,
    uses         INTEGER NOT NULL DEFAULT 0,
    mode         TEXT NOT NULL DEFAULT 'destroy',
    created_at   TEXT NOT NULL,
    expires_at   TEXT,
    destroyed_at TEXT,
    disabled_at  TEXT
);
CREATE INDEX IF NOT EXISTS legacy_owner ON legacy_links(account_id, id DESC);

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

CREATE TABLE IF NOT EXISTS verify_tokens (
    token      TEXT PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS login_attempts (
    key        TEXT PRIMARY KEY,   -- sha256(email) + hmac(ip), never the raw IP
    fails      INTEGER NOT NULL DEFAULT 0,
    first_fail TEXT NOT NULL
);
"""

TRACKING_TABLES = ("opens", "visitors", "share_tokens", "alerts")


def connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    try:
        return {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
    except sqlite3.DatabaseError:
        return set()


def migrate(conn: sqlite3.Connection) -> list[str]:
    """Bring any older database to the zero-knowledge schema. Idempotent.

    Returns the list of changes applied, for the work log and the tests.
    """
    done: list[str] = []
    cols = _columns(conn, "links")

    # 1. Pre-cutover `links` (had a plaintext `target`) becomes `legacy_links`.
    if cols and "target" in cols:
        conn.execute("ALTER TABLE links RENAME TO legacy_links")
        done.append("links -> legacy_links")

    conn.executescript(SCHEMA)

    # 2. Click history is removed, not archived. Owner instruction 2026-11-26.
    for table in TRACKING_TABLES:
        if _columns(conn, table):
            conn.execute(f"DROP TABLE {table}")
            done.append(f"dropped {table}")

    # 3. Legacy rows lose the columns that described people, keep the ones the
    #    resolver needs.
    legacy = _columns(conn, "legacy_links")
    for col in ("ip", "ua", "referer", "fp"):
        if col in legacy:
            conn.execute(f"ALTER TABLE legacy_links DROP COLUMN {col}")
            done.append(f"legacy_links.{col} dropped")

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
