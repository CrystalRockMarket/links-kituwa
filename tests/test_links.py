"""The zero-knowledge contract: opaque storage, exact budgets, immediate wipe."""
import os
import threading

from app import db as dbmod
from app import security, store

from conftest import b64, make_link, unb64


def test_create_stores_only_opaque_bytes(client, conn):
    sealed = os.urandom(64)
    iv = os.urandom(12)
    data = make_link(client, ciphertext=sealed, iv=iv, raw=True)
    assert data["id"] and data["manage_token"]
    row = conn.execute("SELECT * FROM links WHERE id=?", (data["id"],)).fetchone()
    assert row["ciphertext"] == sealed
    assert row["iv"] == iv
    assert row["uses"] == 0
    # The server knows nothing that describes the destination.
    for banned in ("ip", "ua", "referer", "fingerprint", "target", "note", "key"):
        assert banned not in row.keys()


def test_no_table_has_a_click_column(conn):
    names = {r["name"] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert "opens" not in names and "visitors" not in names and "share_tokens" not in names
    for table in names:
        cols = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
        assert not (cols & {"ip", "ua", "referer", "fp", "last_ip", "user_agent"})


def test_consume_returns_the_blob_once(client, conn):
    sealed = os.urandom(40)
    data = make_link(client, ciphertext=sealed, raw=True)
    first = client.post(f"/api/links/{data['id']}/consume", json={})
    assert first.status_code == 200
    assert unb64(first.get_json()["ciphertext"]) == sealed
    assert first.get_json()["uses_left"] == 0

    second = client.post(f"/api/links/{data['id']}/consume", json={})
    assert second.status_code == 410
    row = conn.execute("SELECT ciphertext, spent_at FROM links WHERE id=?",
                       (data["id"],)).fetchone()
    assert row["ciphertext"] is None
    assert row["spent_at"]


def test_preview_of_page_does_not_consume(client, conn):
    data = make_link(client, raw=True)
    for _ in range(5):
        page = client.get(f"/l/{data['id']}")
        assert page.status_code == 200
        assert data["id"].encode() in page.data
    row = conn.execute("SELECT uses FROM links WHERE id=?", (data["id"],)).fetchone()
    assert row["uses"] == 0
    assert client.get(f"/api/links/{data['id']}").get_json()["uses_left"] == 1


def test_fifty_concurrent_consumes_exactly_one(settings, client, conn):
    data = make_link(client, raw=True)
    path = dbmod.db_path(settings.data_dir)
    wins = []
    lock = threading.Lock()

    def hit():
        c = dbmod.connect(path)
        try:
            r = store.consume(c, data["id"])
            if r.state == "ok":
                with lock:
                    wins.append(r.ciphertext)
        finally:
            c.close()

    threads = [threading.Thread(target=hit) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(wins) == 1, f"expected exactly one winner, got {len(wins)}"
    row = conn.execute("SELECT uses, ciphertext FROM links WHERE id=?",
                       (data["id"],)).fetchone()
    assert row["uses"] == 1
    assert row["ciphertext"] is None


def test_expired_link_returns_410(client, conn):
    data = make_link(client, options={"max_uses": 1, "expires_in": 60}, raw=True)
    conn.execute("UPDATE links SET expires_at=? WHERE id=?",
                 (security.iso_after(seconds=-1), data["id"]))
    resp = client.post(f"/api/links/{data['id']}/consume", json={})
    assert resp.status_code == 410
    assert resp.get_json()["reason"] == "expired"


def test_not_before_blocks_until_time(client, conn):
    data = make_link(client, options={"max_uses": 2, "expires_in": 3600,
                                      "not_before_in": 600}, raw=True)
    resp = client.post(f"/api/links/{data['id']}/consume", json={})
    assert resp.status_code == 410
    assert resp.get_json()["reason"] == "not yet active"


def test_unlimited_link_never_wipes(client, conn):
    data = make_link(client, options={"max_uses": None, "expires_in": 3600}, raw=True)
    for _ in range(3):
        assert client.post(f"/api/links/{data['id']}/consume", json={}).status_code == 200
    row = conn.execute("SELECT uses, ciphertext FROM links WHERE id=?",
                       (data["id"],)).fetchone()
    assert row["uses"] == 3 and row["ciphertext"] is not None


def test_password_requires_salt(client):
    resp = client.post("/api/links", json={
        "ciphertext": b64(os.urandom(32)), "iv": b64(os.urandom(12)),
        "kdf": "pbkdf2-sha256-600k", "options": {"max_uses": 1}})
    assert resp.status_code == 400
    assert "salt" in resp.get_json()["error"]


def test_ciphertext_size_limit(client):
    resp = client.post("/api/links", json={
        "ciphertext": b64(os.urandom(9000)), "iv": b64(os.urandom(12)),
        "options": {"max_uses": 1}})
    assert resp.status_code == 400


def test_manage_token_controls_state_and_delete(client, conn):
    data = make_link(client, raw=True)
    bad = client.post(f"/api/manage/{data['id']}",
                      json={"token": "nope", "action": "state"})
    assert bad.status_code == 404

    state = client.post(f"/api/manage/{data['id']}",
                        json={"token": data["manage_token"], "action": "state"})
    assert state.status_code == 200
    assert state.get_json()["state"] == "active"

    ext = client.post(f"/api/manage/{data['id']}",
                      json={"token": data["manage_token"], "action": "extend",
                            "seconds": 86400})
    assert ext.status_code == 200

    gone = client.post(f"/api/manage/{data['id']}",
                       json={"token": data["manage_token"], "action": "delete"})
    assert gone.status_code == 200
    row = conn.execute("SELECT ciphertext, spent_at FROM links WHERE id=?",
                       (data["id"],)).fetchone()
    assert row["ciphertext"] is None and row["spent_at"]


def test_report_and_disable(client, conn):
    data = make_link(client, raw=True)
    assert client.post(f"/api/links/{data['id']}/report",
                       json={"reason": "phishing", "url": "https://evil.example/"}).status_code == 200
    rep = conn.execute("SELECT * FROM reports WHERE link_id=?", (data["id"],)).fetchone()
    assert rep["url"] == "https://evil.example/"
    assert store.disable(conn, data["id"]) is True
    assert client.post(f"/api/links/{data['id']}/consume", json={}).status_code == 410


def test_sweep_wipes_expired_and_deletes_old_tombstones(conn):
    conn.execute(
        "INSERT INTO links(id, ciphertext, iv, created_at, expires_at) VALUES "
        "('aaaaaaaaaaaaaaaaaaaaaa', x'00', x'00', ?, ?)",
        (security.utcnow(), security.iso_after(seconds=-5)))
    conn.execute(
        "INSERT INTO links(id, created_at, spent_at) VALUES ('bbbbbbbbbbbbbbbbbbbbbb', ?, ?)",
        (security.utcnow(), security.iso_after(days=-30)))
    result = store.sweep(conn)
    assert result["wiped"] == 1
    assert result["deleted"] == 1
    assert conn.execute("SELECT COUNT(*) c FROM links").fetchone()["c"] == 1
    assert conn.execute("SELECT ciphertext FROM links").fetchone()["ciphertext"] is None
