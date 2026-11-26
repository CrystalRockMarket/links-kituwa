"""The zero-knowledge link lifecycle.

The server's whole job is: store an opaque blob, count opens atomically, and
wipe the blob the instant the budget is gone. It never sees a destination, a
note, a password or a key.

The one rule that must never break: a link with ``max_uses = N`` serves exactly
N opens. The check and the increment are a single ``UPDATE … RETURNING`` inside
``BEGIN IMMEDIATE``, so two concurrent requests can never both pass.
"""
from __future__ import annotations

import hashlib
import secrets
import sqlite3
from dataclasses import dataclass

from . import security

MAX_CIPHERTEXT = 8 * 1024
MAX_USES = 100000
MAX_EXPIRY_S = 30 * 86400
TOMBSTONE_DAYS = 7


def new_id() -> str:
    """128 bits of entropy, base64url, no padding."""
    return secrets.token_urlsafe(16)


def manage_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@dataclass
class Open:
    state: str                 # ok | gone | missing
    reason: str = ""
    ciphertext: bytes | None = None
    iv: bytes | None = None
    salt: bytes | None = None
    kdf: str = "none"
    redirect_mode: str = "auto"
    uses_left: int | None = None
    max_uses: int | None = None


def create(
    conn: sqlite3.Connection,
    *,
    ciphertext: bytes,
    iv: bytes,
    salt: bytes | None,
    kdf: str,
    max_uses: int | None,
    expires_in: int | None,
    not_before_in: int = 0,
    redirect_mode: str = "auto",
    has_note: bool = False,
) -> tuple[str, str]:
    """Store a sealed payload. Returns ``(id, manage_token)``."""
    if not ciphertext or len(ciphertext) > MAX_CIPHERTEXT:
        raise ValueError("ciphertext must be 1 byte to 8 KB")
    if len(iv) != 12:
        raise ValueError("iv must be 12 bytes")
    if kdf not in {"none", "pbkdf2-sha256-600k"}:
        raise ValueError("unknown kdf")
    if kdf == "none" and salt is not None:
        raise ValueError("salt is only used with a password")
    if kdf != "none" and (not salt or len(salt) != 16):
        raise ValueError("salt must be 16 bytes when a password is set")
    if max_uses is not None and not (1 <= max_uses <= MAX_USES):
        raise ValueError(f"max_uses must be 1..{MAX_USES} or null")
    if expires_in is not None and not (60 <= expires_in <= MAX_EXPIRY_S):
        raise ValueError("expiry must be between 1 minute and 30 days")
    if not_before_in and not (0 <= not_before_in <= MAX_EXPIRY_S):
        raise ValueError("the activation time must be within 30 days")
    if not_before_in and expires_in is not None and not_before_in >= expires_in:
        raise ValueError("the activation time must be before the expiry")
    if redirect_mode not in {"auto", "manual"}:
        raise ValueError("redirect_mode must be auto or manual")

    now = security.utcnow()
    created = now[:13] + ":00:00+00:00"          # rounded to the hour
    expires_at = security.iso_after(seconds=expires_in) if expires_in else None
    not_before = security.iso_after(seconds=not_before_in) if not_before_in else None
    token = security.new_token(32)

    for _ in range(6):
        link_id = new_id()
        try:
            conn.execute(
                "INSERT INTO links(id, ciphertext, iv, salt, kdf, max_uses, uses, "
                "expires_at, not_before, created_at, redirect_mode, has_note, manage_hash) "
                "VALUES (?,?,?,?,?,?,0,?,?,?,?,?,?)",
                (link_id, ciphertext, iv, salt, kdf, max_uses, expires_at, not_before,
                 created, redirect_mode, 1 if has_note else 0, manage_hash(token)),
            )
            return link_id, token
        except sqlite3.IntegrityError:
            continue
    raise RuntimeError("could not allocate an id")


def _wipe(conn: sqlite3.Connection, link_id: str, now: str) -> None:
    conn.execute(
        "UPDATE links SET ciphertext=NULL, iv=NULL, salt=NULL, spent_at=? WHERE id=?",
        (now, link_id),
    )


def consume(conn: sqlite3.Connection, link_id: str) -> Open:
    """Spend one use and return the sealed payload. Race-safe."""
    now = security.utcnow()
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute(
            """UPDATE links SET uses = uses + 1
                WHERE id = ?
                  AND spent_at IS NULL
                  AND disabled_at IS NULL
                  AND (max_uses IS NULL OR uses < max_uses)
                  AND (expires_at IS NULL OR expires_at > ?)
                  AND (not_before IS NULL OR not_before <= ?)
                RETURNING ciphertext, iv, salt, kdf, redirect_mode, max_uses, uses""",
            (link_id, now, now),
        ).fetchone()
        if row is None:
            conn.execute("ROLLBACK")
            return _explain(conn, link_id, now)
        if row["max_uses"] is not None and row["uses"] >= row["max_uses"]:
            _wipe(conn, link_id, now)
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise

    left = None if row["max_uses"] is None else max(row["max_uses"] - row["uses"], 0)
    return Open("ok", ciphertext=row["ciphertext"], iv=row["iv"], salt=row["salt"],
                kdf=row["kdf"], redirect_mode=row["redirect_mode"],
                uses_left=left, max_uses=row["max_uses"])


def _explain(conn: sqlite3.Connection, link_id: str, now: str) -> Open:
    row = conn.execute(
        "SELECT spent_at, disabled_at, expires_at, not_before FROM links WHERE id=?",
        (link_id,),
    ).fetchone()
    if row is None:
        return Open("missing")
    if row["disabled_at"]:
        return Open("gone", "disabled")
    if row["spent_at"]:
        return Open("gone", "spent")
    if row["expires_at"] and row["expires_at"] <= now:
        return Open("gone", "expired")
    if row["not_before"] and row["not_before"] > now:
        return Open("gone", "not yet active")
    return Open("gone", "spent")


def peek(conn: sqlite3.Connection, link_id: str) -> dict:
    """Public state of a link, without spending a use or revealing content."""
    row = conn.execute(
        "SELECT max_uses, uses, expires_at, not_before, disabled_at, spent_at, has_note, "
        "kdf, created_at FROM links WHERE id=?", (link_id,),
    ).fetchone()
    if row is None:
        return {"exists": False}
    left = None if row["max_uses"] is None else max(row["max_uses"] - row["uses"], 0)
    return {
        "exists": True,
        "uses": row["uses"],
        "max_uses": row["max_uses"],
        "uses_left": left,
        "expires_at": row["expires_at"],
        "not_before": row["not_before"],
        "state": state_of(row),
        "has_note": bool(row["has_note"]),
        "kdf": row["kdf"],
        "created_at": row["created_at"],
    }


def state_of(row: sqlite3.Row) -> str:
    if row["spent_at"]:
        return "spent"
    if row["disabled_at"]:
        return "disabled"
    if row["expires_at"] and row["expires_at"] <= security.utcnow():
        return "expired"
    if row["not_before"] and row["not_before"] > security.utcnow():
        return "scheduled"
    if row["max_uses"] is not None and row["uses"] >= row["max_uses"]:
        return "spent"
    return "active"


# --- creator controls, authorised by the manage token ----------------------

def _owned(conn: sqlite3.Connection, link_id: str, token: str) -> sqlite3.Row | None:
    if not link_id or not token:
        return None
    row = conn.execute("SELECT * FROM links WHERE id=?", (link_id,)).fetchone()
    if row is None or not row["manage_hash"]:
        return None
    if not secrets.compare_digest(row["manage_hash"], manage_hash(token)):
        return None
    return row


def manage(conn: sqlite3.Connection, link_id: str, token: str,
           action: str, seconds: int | None = None) -> dict:
    row = _owned(conn, link_id, token)
    if row is None:
        return {"ok": False, "error": "not found"}
    now = security.utcnow()
    if action == "state":
        pass
    elif action == "delete":
        _wipe(conn, link_id, now)
    elif action in {"extend", "shorten"}:
        if not seconds or not (60 <= seconds <= MAX_EXPIRY_S):
            return {"ok": False, "error": "expiry must be between 1 minute and 30 days"}
        if action == "extend":
            base = row["expires_at"] if row["expires_at"] and row["expires_at"] > now else now
            new = security.iso_from(base, seconds=seconds)
        else:
            new = security.iso_after(seconds=seconds)
        conn.execute("UPDATE links SET expires_at=? WHERE id=?", (new, link_id))
        row = conn.execute("SELECT * FROM links WHERE id=?", (link_id,)).fetchone()
    else:
        return {"ok": False, "error": "unknown action"}
    state = peek(conn, link_id)
    state["ok"] = True
    return state


# --- abuse handling --------------------------------------------------------

def report(conn: sqlite3.Connection, link_id: str, reason: str, url: str | None) -> bool:
    if not conn.execute("SELECT 1 FROM links WHERE id=?", (link_id,)).fetchone():
        return False
    conn.execute(
        "INSERT INTO reports(link_id, reason, url, created_at) VALUES (?,?,?,?)",
        (link_id, (reason or "")[:500], (url or None), security.utcnow()),
    )
    conn.execute("UPDATE links SET reported=1 WHERE id=?", (link_id,))
    return True


def disable(conn: sqlite3.Connection, link_id: str) -> bool:
    cur = conn.execute("UPDATE links SET disabled_at=? WHERE id=?",
                       (security.utcnow(), link_id))
    return cur.rowcount == 1


# --- retention ------------------------------------------------------------

def sweep(conn: sqlite3.Connection) -> dict:
    """Wipe spent and expired content. Safe to run every minute."""
    now = security.utcnow()
    wiped = conn.execute(
        "UPDATE links SET ciphertext=NULL, iv=NULL, salt=NULL, spent_at=? "
        "WHERE spent_at IS NULL AND expires_at IS NOT NULL AND expires_at <= ?",
        (now, now),
    ).rowcount
    # Keep a contentless tombstone for a week so the URL answers 410 honestly,
    # then remove the row entirely.
    gone = conn.execute(
        "DELETE FROM links WHERE spent_at IS NOT NULL AND spent_at < ?",
        (security.iso_after(days=-TOMBSTONE_DAYS),),
    ).rowcount
    reports = conn.execute(
        "DELETE FROM reports WHERE resolved=1 AND created_at < ?",
        (security.iso_after(days=-30),)).rowcount
    return {"wiped": wiped, "deleted": gone, "reports_deleted": reports}


__all__ = ["Open", "consume", "create", "disable", "manage", "manage_hash",
           "new_id", "peek", "report", "sweep", "state_of"]
