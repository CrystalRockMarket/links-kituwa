"""Link lifecycle: creation, atomic consumption, visitor attribution, alerts.

The one rule that must never break: a link with ``max_uses = N`` serves exactly
N human opens. The counter check and the increment are the same statement inside
a ``BEGIN IMMEDIATE`` transaction, so concurrent requests cannot both pass the
check.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from . import security


@dataclass
class OpenResult:
    state: str          # ok | preview | gone | missing
    reason: str = ""
    target: str = ""
    link: sqlite3.Row | None = None
    uses_left: int | None = None
    interstitial: bool = False


def _alert(conn: sqlite3.Connection, link: sqlite3.Row, kind: str, body: str) -> None:
    account = conn.execute("SELECT alerts FROM accounts WHERE id=?", (link["account_id"],)).fetchone()
    if not account or not account["alerts"]:
        return
    conn.execute(
        "INSERT INTO alerts(account_id, link_id, kind, body, created_at) VALUES (?,?,?,?,?)",
        (link["account_id"], link["id"], kind, body, security.utcnow()),
    )


def _upsert_visitor(conn: sqlite3.Connection, link_id: int, fp: str, ip: str) -> tuple[int, bool]:
    row = conn.execute("SELECT id FROM visitors WHERE link_id=? AND fp=?", (link_id, fp)).fetchone()
    if row:
        conn.execute(
            "UPDATE visitors SET opens=opens+1, last_ip=? WHERE id=?", (ip, row["id"])
        )
        return row["id"], False
    cur = conn.execute(
        "INSERT INTO visitors(link_id, fp, first_seen, opens, last_ip) VALUES (?,?,?,1,?)",
        (link_id, fp, security.utcnow(), ip),
    )
    return int(cur.lastrowid), True


def consume(
    conn: sqlite3.Connection,
    code: str,
    *,
    ip: str,
    ua: str,
    referer: str,
    lang: str,
    via: str = "",
    preview: bool = False,
    skip_increment: bool = False,
    secret: bytes = b"",
    ip_mode: str = "full",
) -> OpenResult:
    """Resolve a short code, consuming one use unless this is a preview fetch.

    ``skip_increment`` is only honoured for tracking links (unlimited uses),
    where the first hit shows an interstitial and the "continue" click must not
    count a second visit. Budgeted links always consume on a real navigation.
    """
    link = conn.execute("SELECT * FROM links WHERE code=?", (code,)).fetchone()
    if link is None:
        return OpenResult("missing")

    if link["disabled_at"] or link["destroyed_at"]:
        return OpenResult("gone", "destroyed", link=link)
    if link["expires_at"] and link["expires_at"] <= security.utcnow():
        return OpenResult("gone", "expired", link=link)

    stored_ip = security.store_ip(ip, ip_mode)
    fp = security.fingerprint(secret, ip, ua, lang)

    if skip_increment and link["mode"] == "track":
        conn.execute(
            "INSERT INTO opens(link_id, ts, ip, ua, referer, via, kind) VALUES (?,?,?,?,?,?, 'continue')",
            (link["id"], security.utcnow(), stored_ip, ua[:512], referer[:512], via or None),
        )
        return OpenResult("ok", target=link["target"], link=link, uses_left=None)

    if preview:
        conn.execute(
            "INSERT INTO opens(link_id, ts, ip, ua, referer, via, kind) VALUES (?,?,?,?,?,?, 'preview')",
            (link["id"], security.utcnow(), stored_ip, ua[:512], referer[:512], via or None),
        )
        return OpenResult("preview", "preview", link=link)

    # --- the guarded increment -------------------------------------------
    conn.execute("BEGIN IMMEDIATE")
    try:
        cur = conn.execute(
            """UPDATE links SET uses = uses + 1
                WHERE id = ?
                  AND destroyed_at IS NULL
                  AND disabled_at IS NULL
                  AND (max_uses IS NULL OR uses < max_uses)
                  AND (expires_at IS NULL OR expires_at > ?)""",
            (link["id"], security.utcnow()),
        )
        if cur.rowcount != 1:
            conn.execute("ROLLBACK")
            return OpenResult("gone", "exhausted", link=link)

        link = conn.execute("SELECT * FROM links WHERE id=?", (link["id"],)).fetchone()
        if link["max_uses"] is not None and link["uses"] >= link["max_uses"]:
            conn.execute("UPDATE links SET destroyed_at=? WHERE id=?",
                         (security.utcnow(), link["id"]))
            link = conn.execute("SELECT * FROM links WHERE id=?", (link["id"],)).fetchone()

        visitor_id, is_new = _upsert_visitor(conn, link["id"], fp, stored_ip)
        if via:
            conn.execute("UPDATE share_tokens SET opens=opens+1 WHERE token=? AND link_id=?",
                         (via, link["id"]))
        conn.execute(
            "INSERT INTO opens(link_id, visitor_id, ts, ip, ua, referer, via, kind) "
            "VALUES (?,?,?,?,?,?,?, 'open')",
            (link["id"], visitor_id, security.utcnow(), stored_ip, ua[:512], referer[:512], via or None),
        )

        label = link["label"] or link["code"]
        if is_new and link["uses"] > 1:
            _alert(conn, link, "new_visitor",
                   f"\u201c{label}\u201d was opened by a new device ({link['uses']} of "
                   f"{link['max_uses'] or '\u221e'} uses). Someone may have forwarded it.")
        if security.referer_is_share(referer):
            _alert(conn, link, "shared",
                   f"\u201c{label}\u201d was opened from {referer[:200]} \u2014 the link was shared.")
        elif via:
            _alert(conn, link, "shared",
                   f"\u201c{label}\u201d was opened through a share link created by an earlier visitor.")
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise

    left = None if link["max_uses"] is None else max(link["max_uses"] - link["uses"], 0)
    return OpenResult("ok", target=link["target"], link=link, uses_left=left,
                      interstitial=link["mode"] == "track")


def mint_share(conn: sqlite3.Connection, code: str, fp: str) -> str | None:
    """Create a pass-along token so a second hop can be attributed."""
    link = conn.execute("SELECT * FROM links WHERE code=?", (code,)).fetchone()
    if link is None or link["destroyed_at"] or link["disabled_at"]:
        return None
    visitor = conn.execute("SELECT id FROM visitors WHERE link_id=? AND fp=?",
                           (link["id"], fp)).fetchone()
    if visitor is None:
        return None
    token = security.new_token(9)
    conn.execute(
        "INSERT INTO share_tokens(token, link_id, visitor_id, created_at) VALUES (?,?,?,?)",
        (token, link["id"], visitor["id"], security.utcnow()),
    )
    conn.execute("INSERT INTO opens(link_id, visitor_id, ts, kind) VALUES (?,?,?,'share')",
                 (link["id"], visitor["id"], security.utcnow()))
    _alert(conn, link, "passed_on",
           f"“{link['label'] or link['code']}” was passed on to another person.")
    return token


def create_link(
    conn: sqlite3.Connection,
    account_id: int,
    *,
    target: str,
    label: str = "",
    max_uses: int | None = 1,
    mode: str = "destroy",
    expires_days: int | None = None,
) -> sqlite3.Row:
    clean = security.normalise_target(target)
    if clean is None:
        raise ValueError("That destination is not a valid http(s) URL.")
    if max_uses is not None and not (1 <= max_uses <= 100000):
        raise ValueError("Uses must be between 1 and 100000, or unlimited.")
    if mode not in {"destroy", "track"}:
        raise ValueError("Unknown mode.")
    expires_at = security.iso_after(days=expires_days) if expires_days else None
    for _ in range(6):
        code = security.new_code()
        try:
            cur = conn.execute(
                "INSERT INTO links(account_id, code, target, label, max_uses, uses, mode, created_at, expires_at)"
                " VALUES (?,?,?,?,?,0,?,?,?)",
                (account_id, code, clean, label.strip()[:120], max_uses, mode,
                 security.utcnow(), expires_at),
            )
            return conn.execute("SELECT * FROM links WHERE id=?", (int(cur.lastrowid),)).fetchone()
        except sqlite3.IntegrityError:
            continue
    raise RuntimeError("Could not allocate a unique code.")


def link_summary(conn: sqlite3.Connection, link_id: int) -> dict:
    row = conn.execute("SELECT * FROM links WHERE id=?", (link_id,)).fetchone()
    if row is None:
        return {}
    visitors = conn.execute("SELECT COUNT(*) c FROM visitors WHERE link_id=?", (link_id,)).fetchone()["c"]
    shares = conn.execute("SELECT COUNT(*) c FROM share_tokens WHERE link_id=?", (link_id,)).fetchone()["c"]
    alerts = conn.execute("SELECT COUNT(*) c FROM alerts WHERE link_id=?", (link_id,)).fetchone()["c"]
    previews = conn.execute("SELECT COUNT(*) c FROM opens WHERE link_id=? AND kind='preview'",
                            (link_id,)).fetchone()["c"]
    return {
        "link": row, "visitors": visitors, "shares": shares,
        "alerts": alerts, "previews": previews,
    }


def state_of(link: sqlite3.Row) -> str:
    if link["destroyed_at"]:
        return "destroyed"
    if link["disabled_at"]:
        return "paused"
    if link["expires_at"] and link["expires_at"] <= security.utcnow():
        return "expired"
    if link["max_uses"] is not None and link["uses"] >= link["max_uses"]:
        return "used up"
    return "active"


__all__ = ["OpenResult", "consume", "create_link", "link_summary", "mint_share", "state_of", "json"]
