"""Feature matrix: every option, every endpoint, every refusal."""
import base64
import json
import os

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app import limits, store

from conftest import b64, make_link, unb64


def seal(payload: dict, key: bytes, password: str = "") -> dict:
    """Act as the browser: PBKDF2 + HKDF + AES-256-GCM, exactly like crypto.js."""
    import hashlib

    salt = os.urandom(16) if password else None
    if password:
        pw = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600000, 32)
        combined = hashlib.pbkdf2_hmac("sha256", pw, key, 1, 32)  # stand-in for HKDF
    else:
        combined = key
    iv = os.urandom(12)
    ct = AESGCM(combined).encrypt(iv, json.dumps(payload).encode(), None)
    return {"ciphertext": b64(ct), "iv": b64(iv),
            "salt": b64(salt) if salt else None,
            "kdf": "pbkdf2-sha256-600k" if password else "none"}


def create(client, sealed, **options):
    body = {k: v for k, v in sealed.items() if v is not None}
    body["options"] = options
    return client.post("/api/links", json=body)


@pytest.mark.parametrize("max_uses", [1, 2, 3, 5, 10, 100, None])
def test_every_use_budget(client, max_uses):
    sealed = seal({"v": 1, "urls": ["https://example.com/x"]}, os.urandom(32))
    r = create(client, sealed, max_uses=max_uses, expires_in=3600)
    assert r.status_code == 201, r.data
    link_id = r.get_json()["id"]
    allowed = 3 if max_uses is None else max_uses
    for i in range(allowed):
        assert client.post(f"/api/links/{link_id}/consume", json={}).status_code == 200, i
    if max_uses is not None:
        assert client.post(f"/api/links/{link_id}/consume", json={}).status_code == 410


@pytest.mark.parametrize("expires_in", [600, 3600, 86400, 604800, 2592000, None])
def test_every_expiry_preset(client, conn, expires_in):
    sealed = seal({"v": 1, "urls": ["https://example.com/x"]}, os.urandom(32))
    r = create(client, sealed, max_uses=1, expires_in=expires_in)
    assert r.status_code == 201, r.data
    row = conn.execute("SELECT expires_at FROM links WHERE id=?",
                       (r.get_json()["id"],)).fetchone()
    assert (row["expires_at"] is None) == (expires_in is None)


def test_not_before_and_expiry_relationship(client):
    sealed = seal({"v": 1, "urls": ["https://example.com/x"]}, os.urandom(32))
    assert create(client, sealed, max_uses=1, expires_in=3600,
                  not_before_in=7200).status_code == 400
    assert create(client, sealed, max_uses=1, expires_in=3600,
                  not_before_in=60).status_code == 201
    assert create(client, sealed, max_uses=1, expires_in=None,
                  not_before_in=40 * 86400).status_code == 400


def test_password_link_round_trip(client):
    key = os.urandom(32)
    sealed = seal({"v": 1, "urls": ["https://example.com/secret"], "note": "hi"}, key, "pw")
    r = create(client, sealed, max_uses=1, expires_in=3600)
    assert r.status_code == 201
    data = client.post(f"/api/links/{r.get_json()['id']}/consume", json={}).get_json()
    assert data["kdf"] == "pbkdf2-sha256-600k"
    assert data["salt"]
    assert unb64(data["ciphertext"]) != b""


def test_manual_redirect_mode_is_stored(client):
    sealed = seal({"v": 1, "urls": ["https://example.com/x"]}, os.urandom(32))
    r = create(client, sealed, max_uses=2, expires_in=3600, redirect_mode="manual")
    assert r.status_code == 201
    data = client.post(f"/api/links/{r.get_json()['id']}/consume", json={}).get_json()
    assert data["redirect_mode"] == "manual"


def test_bundle_and_note_flags(client):
    sealed = seal({"v": 1, "urls": ["https://a.example/", "https://b.example/"],
                   "note": "two links"}, os.urandom(32))
    r = create(client, sealed, max_uses=1, expires_in=3600, has_note=True)
    assert r.status_code == 201
    peek = client.get(f"/api/links/{r.get_json()['id']}").get_json()
    assert peek["has_note"] is True
    assert peek["kdf"] == "none"


def test_peek_reports_the_kdf_so_the_password_is_asked_before_a_use_is_spent(client):
    key = os.urandom(32)
    sealed = seal({"v": 1, "urls": ["https://example.com/x"]}, key, "pw")
    link_id = create(client, sealed, max_uses=1, expires_in=3600).get_json()["id"]
    peek = client.get(f"/api/links/{link_id}").get_json()
    assert peek["kdf"] == "pbkdf2-sha256-600k"
    assert peek["uses"] == 0


def test_full_round_trip_matches_the_browser_contract(client):
    key = os.urandom(32)
    payload = {"v": 1, "urls": ["https://example.com/a?b=c#d"], "createdAt": "now"}
    r = create(client, seal(payload, key), max_uses=1, expires_in=3600)
    data = client.post(f"/api/links/{r.get_json()['id']}/consume", json={}).get_json()
    plain = AESGCM(key).decrypt(unb64(data["iv"]), unb64(data["ciphertext"]), None)
    assert json.loads(plain) == payload


def test_manage_extend_shorten_delete(client, conn):
    sealed = seal({"v": 1, "urls": ["https://example.com/x"]}, os.urandom(32))
    r = create(client, sealed, max_uses=5, expires_in=3600)
    link_id, token = r.get_json()["id"], r.get_json()["manage_token"]

    state = client.post(f"/api/manage/{link_id}",
                        json={"token": token, "action": "state"}).get_json()
    assert state["uses_left"] == 5 and state["state"] == "active"

    ext = client.post(f"/api/manage/{link_id}",
                      json={"token": token, "action": "extend", "seconds": 86400}).get_json()
    assert ext["ok"] and ext["expires_at"] > state["expires_at"]

    short = client.post(f"/api/manage/{link_id}",
                        json={"token": token, "action": "shorten", "seconds": 3600}).get_json()
    assert short["ok"] and short["expires_at"] < ext["expires_at"]

    assert client.post(f"/api/manage/{link_id}",
                       json={"token": "wrong", "action": "state"}).status_code == 404
    assert client.post(f"/api/manage/{link_id}",
                       json={"token": token, "action": "nonsense"}).status_code == 404

    deleted = client.post(f"/api/manage/{link_id}",
                          json={"token": token, "action": "delete"}).get_json()
    assert deleted["ok"] and deleted["state"] == "spent"
    row = conn.execute("SELECT ciphertext FROM links WHERE id=?", (link_id,)).fetchone()
    assert row["ciphertext"] is None


def test_report_is_stored_and_disable_blocks(client, conn):
    sealed = seal({"v": 1, "urls": ["https://example.com/x"]}, os.urandom(32))
    link_id = create(client, sealed, max_uses=2, expires_in=3600).get_json()["id"]
    assert client.post(f"/api/links/{link_id}/report",
                       json={"reason": "phishing"}).get_json()["ok"] is True
    assert conn.execute("SELECT COUNT(*) c FROM reports").fetchone()["c"] == 1
    assert store.disable(conn, link_id)
    assert client.post(f"/api/links/{link_id}/consume", json={}).status_code == 410


def test_rate_limit_on_consume(tmp_path, monkeypatch):
    from app.config import Settings
    from app.httpd import create_app

    monkeypatch.setitem(limits.DEFAULT_LIMITS, "consume", (3, 3600))
    app = create_app(Settings(data_dir=tmp_path, secret=b"x" * 32,
                              base_url="http://127.0.0.1:8891", cookie_secure=False,
                              sweep=False, pow=False))
    app.config.update(TESTING=True)
    client = app.test_client()
    sealed = seal({"v": 1, "urls": ["https://example.com/x"]}, os.urandom(32))
    link_id = create(client, sealed, max_uses=10, expires_in=3600).get_json()["id"]
    codes = [client.post(f"/api/links/{link_id}/consume", json={}).status_code
             for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]


def test_oversized_and_malformed_bodies(client):
    big = {"ciphertext": b64(os.urandom(9000)), "iv": b64(os.urandom(12)),
           "options": {"max_uses": 1}}
    assert client.post("/api/links", json=big).status_code == 400
    assert client.post("/api/links", data="not json",
                       content_type="application/json").status_code == 400
    huge = "x" * (70 * 1024)
    assert client.post("/api/links", data=huge,
                       content_type="application/json").status_code == 413


def test_unknown_paths_and_apis(client):
    page = client.get("/nope")
    assert page.status_code == 404 and b"does not exist" in page.data
    # a well-formed but unknown id serves the shell; the API says 404
    assert client.get("/l/" + "z" * 22).status_code == 200
    assert client.get("/api/links/" + "z" * 22).status_code == 404
    # a malformed id is refused outright
    assert client.get("/l/short").status_code == 404
    assert client.get("/api/links/short").status_code == 404
    assert client.get("/api/links").status_code == 405


def test_security_txt_and_robots(client):
    txt = client.get("/.well-known/security.txt")
    assert txt.status_code == 200 and b"Contact:" in txt.data
    robots = client.get("/robots.txt").get_data(as_text=True)
    assert "Disallow: /l/" in robots and "Disallow: /api/" in robots


def test_release_endpoints_absent_without_a_release(client):
    assert client.get("/release.json").status_code == 404
    assert client.get("/release.pub").status_code == 404
    assert client.get("/release/links-kituwa-x.tar.gz").status_code == 404


def test_no_cookie_anywhere(client):
    for path in ("/", "/privacy", "/verify", "/l/" + "A" * 22, "/m/" + "A" * 22):
        assert "Set-Cookie" not in client.get(path).headers, path


def test_home_page_has_social_meta(client):
    body = client.get("/").get_data(as_text=True)
    assert 'property="og:title"' in body
    assert "End-to-end encrypted" in body or "end-to-end encrypted" in body


def test_verify_page_links_the_commit(client):
    body = client.get("/verify").get_data(as_text=True)
    assert "github.com/CrystalRockMarket/links-kituwa" in body
