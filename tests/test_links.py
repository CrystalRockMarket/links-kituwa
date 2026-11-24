"""The destructive-link contract: exact budgets, atomic decrement, previews free."""
import threading

import pytest

from app import db as dbmod
from app import security, tracking


def make_link(conn, account_id, **kw):
    return tracking.create_link(conn, account_id, target="https://example.com/x", **kw)


def open_once(conn, code, ua="Mozilla/5.0 test", ip="203.0.113.9", referer=""):
    return tracking.consume(conn, code, ip=ip, ua=ua, referer=referer, lang="en",
                            secret=b"s", ip_mode="full")


def test_one_time_link_dies_on_first_open(conn):
    acc = conn.execute("INSERT INTO accounts(email,pw_hash,created_at) VALUES ('a@b.c','x','t')").lastrowid
    link = make_link(conn, acc)
    assert link["max_uses"] == 1

    first = open_once(conn, link["code"])
    assert first.state == "ok"
    assert first.uses_left == 0

    second = open_once(conn, link["code"], ua="Mozilla/5.0 other")
    assert second.state == "gone" and second.reason == "destroyed"

    row = conn.execute("SELECT * FROM links WHERE id=?", (link["id"],)).fetchone()
    assert row["uses"] == 1
    assert row["destroyed_at"] is not None
    assert tracking.state_of(row) == "destroyed"


def test_three_use_link_stops_at_three(conn):
    acc = conn.execute("INSERT INTO accounts(email,pw_hash,created_at) VALUES ('a@b.c','x','t')").lastrowid
    link = make_link(conn, acc, max_uses=3)
    results = [open_once(conn, link["code"], ua=f"Mozilla/5.0 device{i}").state for i in range(5)]
    assert results == ["ok", "ok", "ok", "gone", "gone"]


def test_preview_never_consumes(tmp_path):
    path = dbmod.db_path(tmp_path)
    dbmod.init_db(path)
    c = dbmod.connect(path)
    acc = c.execute("INSERT INTO accounts(email,pw_hash,created_at) VALUES ('a@b.c','x','t')").lastrowid
    link = tracking.create_link(c, acc, target="https://example.com/")
    res = tracking.consume(c, link["code"], ip="1.1.1.1", ua="facebookexternalhit/1.1",
                           referer="", lang="en", preview=True, secret=b"s")
    assert res.state == "preview"
    row = c.execute("SELECT uses, destroyed_at FROM links WHERE id=?", (link["id"],)).fetchone()
    assert row["uses"] == 0 and row["destroyed_at"] is None
    c.close()


def test_concurrent_opens_cannot_exceed_budget(tmp_path):
    path = dbmod.db_path(tmp_path)
    dbmod.init_db(path)
    setup = dbmod.connect(path)
    acc = setup.execute("INSERT INTO accounts(email,pw_hash,created_at) VALUES ('a@b.c','x','t')").lastrowid
    link = tracking.create_link(setup, acc, target="https://example.com/", max_uses=3)
    code = link["code"]
    setup.close()

    won, errors = [], []
    barrier = threading.Barrier(10)

    def racer(i):
        conn = dbmod.connect(path)
        try:
            barrier.wait()
            r = tracking.consume(conn, code, ip=f"198.51.100.{i}", ua=f"Mozilla/5.0 d{i}",
                                 referer="", lang="en", secret=b"s")
            if r.state == "ok":
                won.append(i)
        except Exception as exc:  # noqa: BLE001
            errors.append(repr(exc))
        finally:
            conn.close()

    threads = [threading.Thread(target=racer, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    check = dbmod.connect(path)
    row = check.execute("SELECT uses, max_uses FROM links WHERE code=?", (code,)).fetchone()
    check.close()
    assert not errors
    assert len(won) == 3
    assert row["uses"] == 3


def test_unlimited_link_never_closes(conn):
    acc = conn.execute("INSERT INTO accounts(email,pw_hash,created_at) VALUES ('a@b.c','x','t')").lastrowid
    link = make_link(conn, acc, max_uses=None, mode="track")
    for i in range(12):
        assert open_once(conn, link["code"], ua=f"Mozilla/5.0 d{i}").state == "ok"
    row = conn.execute("SELECT uses, destroyed_at FROM links WHERE id=?", (link["id"],)).fetchone()
    assert row["uses"] == 12 and row["destroyed_at"] is None


def test_expired_link_is_closed(conn):
    acc = conn.execute("INSERT INTO accounts(email,pw_hash,created_at) VALUES ('a@b.c','x','t')").lastrowid
    link = make_link(conn, acc, max_uses=None, mode="track")
    conn.execute("UPDATE links SET expires_at='2000-01-01T00:00:00' WHERE id=?", (link["id"],))
    assert open_once(conn, link["code"]).reason == "expired"


def test_new_device_and_referrer_raise_alerts(conn):
    acc = conn.execute("INSERT INTO accounts(email,pw_hash,created_at) VALUES ('a@b.c','x','t')").lastrowid
    link = make_link(conn, acc, max_uses=4, label="Invoice")
    open_once(conn, link["code"], ua="Mozilla/5.0 phone")
    open_once(conn, link["code"], ua="Mozilla/5.0 laptop", referer="https://mail.google.com/mail/u/0")
    kinds = [r["kind"] for r in conn.execute("SELECT kind FROM alerts ORDER BY id").fetchall()]
    assert "new_visitor" in kinds
    assert "shared" in kinds


@pytest.mark.parametrize("target", ["javascript:alert(1)", "data:text/html,hi", "file:///etc/passwd",
                                    "https://user:pw@example.com/", "http://", ""])
def test_unsafe_targets_rejected(conn, target):
    acc = conn.execute("INSERT INTO accounts(email,pw_hash,created_at) VALUES ('a@b.c','x','t')").lastrowid
    with pytest.raises(ValueError):
        tracking.create_link(conn, acc, target=target)


def test_bare_domain_gets_https(conn):
    acc = conn.execute("INSERT INTO accounts(email,pw_hash,created_at) VALUES ('a@b.c','x','t')").lastrowid
    link = tracking.create_link(conn, acc, target="example.com/page")
    assert link["target"] == "https://example.com/page"


def test_ip_privacy_modes():
    assert security.store_ip("203.0.113.42", "full") == "203.0.113.42"
    assert security.store_ip("203.0.113.42", "truncated") == "203.0.113.0/24"
    assert security.store_ip("2001:db8:1:2::9", "truncated") == "2001:db8:1::/48"
    assert len(security.store_ip("203.0.113.42", "hashed")) == 24


def test_preview_detection():
    assert security.is_preview("WhatsApp/2.23", "")
    assert security.is_preview("Mozilla/5.0", "prefetch")
    assert not security.is_preview("Mozilla/5.0 (iPhone) Safari", "")
