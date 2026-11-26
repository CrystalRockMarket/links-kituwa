"""Pages, headers, the migration, and the things that must never be stored."""
import hashlib
import sqlite3

import pytest

from app import db as dbmod
from app import limits, security

from conftest import make_link


def test_headers_on_every_route(client):
    link = make_link(client, raw=True)
    paths = ["/", "/privacy", "/verify", "/robots.txt", "/healthz",
             f"/l/{link['id']}", f"/m/{link['id']}", f"/api/links/{link['id']}",
             "/release.json", "/does-not-exist"]
    for path in paths:
        resp = client.get(path)
        h = resp.headers
        assert h["X-Content-Type-Options"] == "nosniff", path
        assert h["Referrer-Policy"] == "no-referrer", path
        assert h["X-Frame-Options"] == "DENY", path
        assert h["Cross-Origin-Opener-Policy"] == "same-origin", path
        assert "camera=()" in h["Permissions-Policy"], path
        assert h["Strict-Transport-Security"].startswith("max-age=63072000"), path
        assert "preload" in h["Strict-Transport-Security"], path
        csp = h["Content-Security-Policy"]
        assert "default-src 'self'" in csp, path
        assert "object-src 'none'" in csp and "base-uri 'none'" in csp, path
        assert "frame-ancestors 'none'" in csp, path


def test_secret_pages_have_no_third_party_and_no_cookie(client):
    link = make_link(client, raw=True)
    for path in (f"/l/{link['id']}", f"/m/{link['id']}"):
        resp = client.get(path)
        body = resp.data.decode()
        assert "kituwa-network" not in body
        assert "hub.kituwa.com" not in body
        assert "hub.kituwa.com" not in resp.headers["Content-Security-Policy"]
        assert "Set-Cookie" not in resp.headers
        assert resp.headers["Cache-Control"].startswith("no-store")
        # Every script on the page is same-origin and hash-pinned.
        for line in body.splitlines():
            if "<script" in line and "src=" in line:
                assert "/static/" in line
                assert "integrity=\"sha384-" in line


def test_home_page_keeps_the_network_bar(client):
    body = client.get("/").data.decode()
    assert "<kituwa-network" in body
    assert "kituwa-network/v5/network.js" in body


def test_api_never_sets_a_cookie(client):
    resp = client.post("/api/links", json={
        "ciphertext": "AAAA", "iv": "AAAAAAAAAAAAAAAA", "options": {"max_uses": 1}})
    assert "Set-Cookie" not in resp.headers


def test_migration_purges_click_history(tmp_path):
    path = tmp_path / "old.sqlite3"
    old = sqlite3.connect(path)
    old.executescript("""
        CREATE TABLE accounts (id INTEGER PRIMARY KEY, email TEXT, pw_hash TEXT, created_at TEXT);
        CREATE TABLE links (id INTEGER PRIMARY KEY, account_id INTEGER, code TEXT UNIQUE,
            target TEXT, label TEXT, max_uses INTEGER, uses INTEGER, mode TEXT,
            created_at TEXT, expires_at TEXT, destroyed_at TEXT, disabled_at TEXT);
        CREATE TABLE visitors (id INTEGER PRIMARY KEY, link_id INTEGER, fp TEXT, first_seen TEXT,
            opens INTEGER, last_ip TEXT);
        CREATE TABLE opens (id INTEGER PRIMARY KEY, link_id INTEGER, visitor_id INTEGER, ts TEXT,
            ip TEXT, ua TEXT, referer TEXT, via TEXT, kind TEXT);
        CREATE TABLE share_tokens (token TEXT PRIMARY KEY, link_id INTEGER, visitor_id INTEGER,
            created_at TEXT, opens INTEGER);
        CREATE TABLE alerts (id INTEGER PRIMARY KEY, account_id INTEGER, link_id INTEGER,
            kind TEXT, body TEXT, created_at TEXT, seen INTEGER);
    """)
    old.execute("INSERT INTO links(code,target,max_uses,uses,created_at) "
                "VALUES ('abcd2345','https://example.com/secret',3,1,'2026-01-01T00:00:00+00:00')")
    old.execute("INSERT INTO opens(link_id,ts,ip,ua,referer,kind) "
                "VALUES (1,'2026-01-01T00:00:00+00:00','203.0.113.5','UA','https://mail.x/','open')")
    old.execute("INSERT INTO visitors(link_id,fp,first_seen,opens,last_ip) "
                "VALUES (1,'fp','2026-01-01T00:00:00+00:00',1,'203.0.113.5')")
    old.commit()
    old.close()

    changes = dbmod.init_db(path)
    assert any("legacy_links" in c for c in changes)

    conn = dbmod.connect(path)
    tables = {r["name"] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert not (tables & {"opens", "visitors", "share_tokens", "alerts"})
    row = conn.execute("SELECT * FROM legacy_links").fetchone()
    assert row["code"] == "abcd2345"
    assert row["target"] == "https://example.com/secret"
    conn.close()


def test_rate_limit_on_creation(client):
    payload = {"ciphertext": "AAAA", "iv": "AAAAAAAAAAAAAAAA", "options": {"max_uses": 1}}
    codes = [client.post("/api/links", json=payload).status_code for _ in range(21)]
    assert codes[:20] == [201] * 20
    assert codes[20] == 429


def test_proof_of_work_when_under_pressure(tmp_path, monkeypatch):
    from app.config import Settings
    from app.httpd import create_app

    monkeypatch.setattr(limits, "PRESSURE_LIMIT", 2)
    app = create_app(Settings(data_dir=tmp_path, secret=b"x" * 32,
                              base_url="http://127.0.0.1:8891", cookie_secure=False,
                              sweep=False, pow=True))
    app.config.update(TESTING=True)
    client = app.test_client()
    payload = {"ciphertext": "AAAA", "iv": "AAAAAAAAAAAAAAAA", "options": {"max_uses": 1}}
    assert client.post("/api/links", json=payload).status_code == 201
    second = client.post("/api/links", json=payload)
    assert second.status_code == 428 and second.get_json()["pow"] is True

    chal = client.get("/api/pow").get_json()
    token, bits = chal["challenge"], chal["bits"]
    n = 0
    while True:
        digest = hashlib.sha256(f"{token}:{n}".encode()).digest()
        if int.from_bytes(digest[:3], "big") >> (24 - bits) == 0:
            break
        n += 1
    ok = client.post("/api/links", json={**payload, "pow": {"challenge": token,
                                                            "solution": str(n)}})
    assert ok.status_code == 201


def test_invalid_ids_are_404(client):
    for bad in ("short", "x" * 23, "AAAAAAAAAAAAAAAAAAAAAA!"):
        assert client.get(f"/l/{bad}").status_code == 404
        assert client.post(f"/api/links/{bad}/consume", json={}).status_code == 404


def test_open_legacy_path_cannot_shadow_static_routes(client):
    assert client.get("/privacy").status_code == 200
    assert client.get("/verify").status_code == 200
    assert client.get("/admin").status_code in (302, 303)
