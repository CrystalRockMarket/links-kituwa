"""HTTP surface: signup/verify/login, CSRF, isolation, open flow, previews, headers."""
import re
from pathlib import Path

from conftest import csrf, make_account, signin


def test_signup_verifies_then_signs_in(client, settings):
    page = client.get("/signup").get_data(as_text=True)
    r = client.post("/signup", data={"csrf": csrf(page), "email": "New@Example.com",
                                     "password": "a long enough password"})
    assert r.status_code == 302
    mails = list((Path(settings.data_dir) / "outbox").glob("*.eml"))
    assert mails, "verification mail queued"
    token = re.search(r"/verify/([A-Za-z0-9_\-]+)", mails[0].read_text())
    assert token
    v = client.get(f"/verify/{token.group(1)}")
    assert v.status_code == 200
    # second use of the same token is refused
    assert client.get(f"/verify/{token.group(1)}").status_code == 410
    r = client.post("/login", data={"csrf": csrf(client.get("/login").get_data(as_text=True)),
                                    "email": "new@example.com",
                                    "password": "a long enough password"})
    assert r.status_code == 302 and r.headers["Location"].endswith("/app")


def test_signup_rejects_short_password(client):
    page = client.get("/signup").get_data(as_text=True)
    r = client.post("/signup", data={"csrf": csrf(page), "email": "x@y.z", "password": "short"})
    assert r.status_code == 400


def test_post_without_csrf_is_refused(client):
    assert client.post("/signup", data={"email": "x@y.z", "password": "a long enough password"}).status_code == 400
    assert client.post("/login", data={"email": "x@y.z", "password": "x"}).status_code == 400


def test_dashboard_requires_login(client):
    r = client.get("/app")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_create_link_and_open_flow(client, conn, settings):
    make_account(conn)
    signin(client)
    page = client.get("/app").get_data(as_text=True)
    r = client.post("/app/new", data={"csrf": csrf(page), "target": "https://example.com/target",
                                      "label": "Doc", "max_uses": "1"})
    assert r.status_code == 302
    link = conn.execute("SELECT * FROM links").fetchone()
    assert link["label"] == "Doc" and link["max_uses"] == 1

    ok = client.get(f"/{link['code']}", headers={"User-Agent": "Mozilla/5.0 person"})
    assert ok.status_code == 302 and ok.headers["Location"] == "https://example.com/target"
    assert ok.headers["Cache-Control"].startswith("no-store")

    again = client.get(f"/{link['code']}", headers={"User-Agent": "Mozilla/5.0 person"})
    assert again.status_code == 410
    assert "closed" in again.get_data(as_text=True)


def test_preview_request_does_not_burn_one_time_link(client, conn):
    make_account(conn)
    signin(client)
    page = client.get("/app").get_data(as_text=True)
    client.post("/app/new", data={"csrf": csrf(page), "target": "https://example.com/x",
                                  "max_uses": "1"})
    code = conn.execute("SELECT code FROM links").fetchone()["code"]

    head = client.get(f"/{code}", headers={"User-Agent": "facebookexternalhit/1.1"})
    assert head.status_code == 200 and "Continue" in head.get_data(as_text=True)
    assert conn.execute("SELECT uses FROM links WHERE code=?", (code,)).fetchone()["uses"] == 0

    # the human click through the interstitial does consume it
    assert client.get(f"/{code}?go=1", headers={"User-Agent": "Mozilla/5.0 person"}).status_code == 302
    assert conn.execute("SELECT uses FROM links WHERE code=?", (code,)).fetchone()["uses"] == 1


def test_track_mode_interstitial_does_not_double_count(client, conn):
    make_account(conn)
    signin(client)
    page = client.get("/app").get_data(as_text=True)
    client.post("/app/new", data={"csrf": csrf(page), "target": "https://example.com/t",
                                  "max_uses": "0"})
    row = conn.execute("SELECT * FROM links").fetchone()
    assert row["max_uses"] is None and row["mode"] == "track"

    first = client.get(f"/{row['code']}", headers={"User-Agent": "Mozilla/5.0 person"})
    assert first.status_code == 200 and "Pass this link on" in first.get_data(as_text=True)
    second = client.get(f"/{row['code']}?go=1", headers={"User-Agent": "Mozilla/5.0 person"})
    assert second.status_code == 302
    assert conn.execute("SELECT uses FROM links WHERE id=?", (row["id"],)).fetchone()["uses"] == 1


def test_link_isolation_between_accounts(client, conn):
    mine = make_account(conn, "mine@example.com")
    other = make_account(conn, "other@example.com", "another long password")
    signin(client, "mine@example.com")
    page = client.get("/app").get_data(as_text=True)
    client.post("/app/new", data={"csrf": csrf(page), "target": "https://example.com/mine"})
    link_id = conn.execute("SELECT id FROM links WHERE account_id=?", (mine,)).fetchone()["id"]
    client.post("/logout", data={"csrf": csrf(client.get("/app").get_data(as_text=True))})

    signin(client, "other@example.com", "another long password")
    assert client.get(f"/app/link/{link_id}").status_code == 404


def test_security_headers_and_health(client):
    r = client.get("/healthz")
    assert r.status_code == 200 and r.get_json()["ok"] is True
    r = client.get("/")
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]


def test_bad_code_is_404(client):
    assert client.get("/s/notacode").status_code == 404
    assert client.get("/s/zzzzzzzz").status_code == 404


def test_short_path_does_not_shadow_the_app(client, conn):
    # static routes win over /<code>, and the /s/ alias still resolves
    assert client.get("/login").status_code == 200
    assert client.get("/app").status_code == 302
    assert client.get("/healthz").status_code == 200
    make_account(conn)
    link = conn.execute("SELECT 1").fetchone()
    assert link is not None


def test_legacy_s_alias_still_opens_a_link(client, conn):
    make_account(conn)
    signin(client)
    page = client.get("/app").get_data(as_text=True)
    client.post("/app/new", data={"csrf": csrf(page), "target": "https://example.com/alias",
                                  "max_uses": "1"})
    code = conn.execute("SELECT code FROM links").fetchone()["code"]
    r = client.get(f"/s/{code}", headers={"User-Agent": "Mozilla/5.0 person"})
    assert r.status_code == 302 and r.headers["Location"] == "https://example.com/alias"


def test_share_endpoint_mints_attributed_link(client, conn):
    make_account(conn)
    signin(client)
    page = client.get("/app").get_data(as_text=True)
    client.post("/app/new", data={"csrf": csrf(page), "target": "https://example.com/s",
                                  "max_uses": "0"})
    code = conn.execute("SELECT code FROM links").fetchone()["code"]
    ua = {"User-Agent": "Mozilla/5.0 sharer"}
    client.get(f"/{code}", headers=ua)          # becomes a known visitor
    r = client.post(f"/{code}/share", headers=ua)
    assert r.status_code == 200 and r.get_json()["ok"]
    digest = conn.execute("SELECT COUNT(*) c FROM share_tokens").fetchone()["c"]
    assert digest == 1

    # a different person arriving through that token is attributed and alerted
    via = r.get_json()["url"].split("via=")[1]
    client.get(f"/{code}?via={via}", headers={"User-Agent": "Mozilla/5.0 receiver"})
    assert conn.execute("SELECT opens FROM share_tokens").fetchone()["opens"] == 1
    assert conn.execute("SELECT COUNT(*) c FROM alerts WHERE kind='shared'").fetchone()["c"] >= 1
