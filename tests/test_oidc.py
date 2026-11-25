"""Pocket ID operator console: redirect starts, state/nonce/audience/group checks."""
import base64
import json
import time

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app import oidc


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


@pytest.fixture(scope="module")
def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def jwks(key):
    numbers = key.public_key().public_numbers()
    return {"keys": [{
        "kty": "RSA", "kid": "test", "use": "sig", "alg": "RS256",
        "n": b64(numbers.n.to_bytes(256, "big")),
        "e": b64(numbers.e.to_bytes(3, "big")),
    }]}


def sign(key, claims, kid="test"):
    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    body = f"{b64(json.dumps(header).encode())}.{b64(json.dumps(claims).encode())}"
    sig = key.sign(body.encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{body}.{b64(sig)}"


def claims(**over):
    now = int(time.time())
    base = {"iss": "https://auth.kituwa.com", "aud": "client-1", "sub": "u1",
            "email": "owner@kituwa.com", "exp": now + 300, "iat": now,
            "nonce": "n-1", "groups": ["operators"]}
    base.update(over)
    return base


def test_valid_token_verifies(key, jwks):
    token = sign(key, claims())
    payload = oidc.verify_id_token(token, jwks, "https://auth.kituwa.com", "client-1", nonce="n-1")
    assert payload["sub"] == "u1"
    assert oidc.has_group(payload, "operators")


@pytest.mark.parametrize("mutation,reason", [
    ({"aud": "someone-else"}, "audience"),
    ({"iss": "https://evil.example"}, "issuer"),
    ({"exp": 1000}, "expiry"),
    ({"nonce": "wrong"}, "nonce"),
])
def test_rejections(key, jwks, mutation, reason):
    token = sign(key, claims(**mutation))
    with pytest.raises(oidc.OIDCError):
        oidc.verify_id_token(token, jwks, "https://auth.kituwa.com", "client-1", nonce="n-1")


def test_tampered_payload_is_rejected(key, jwks):
    good = sign(key, claims())
    head, _, sig = good.split(".")
    forged = b64(json.dumps(claims(sub="admin")).encode())
    with pytest.raises(oidc.OIDCError):
        oidc.verify_id_token(f"{head}.{forged}.{sig}", jwks, "https://auth.kituwa.com", "client-1")


def test_unknown_kid_is_rejected(key):
    token = sign(key, claims(), kid="other")
    with pytest.raises(oidc.OIDCError):
        oidc.verify_id_token(token, {"keys": []}, "https://auth.kituwa.com", "client-1")


def test_group_check_handles_dicts_and_strings():
    assert oidc.has_group({"groups": ["operators"]}, "operators")
    assert oidc.has_group({"groups": [{"name": "operators"}]}, "operators")
    assert not oidc.has_group({"groups": ["members"]}, "operators")
    assert not oidc.has_group({}, "operators")


def test_admin_console_requires_sign_in(client):
    r = client.get("/admin")
    assert r.status_code == 302 and "/admin/login" in r.headers["Location"]


def test_admin_login_redirects_to_the_provider(tmp_path, monkeypatch):
    from app.config import Settings
    from app.httpd import create_app

    settings = Settings(data_dir=tmp_path, secret=b"test-secret", base_url="https://links.kituwa.com",
                        oidc_client_id="client-1")
    app = create_app(settings)
    monkeypatch.setattr("app.oidc.begin", lambda *a, **k: {
        "url": "https://auth.kituwa.com/authorize?client_id=client-1&state=s1"
               "&code_challenge=abc&code_challenge_method=S256&nonce=n1",
        "state": "s1", "nonce": "n1", "verifier": "v1",
        "token_endpoint": "https://auth.kituwa.com/api/oidc/token",
    })
    client = app.test_client()
    r = client.get("/admin/login")
    assert r.status_code == 302
    loc = r.headers["Location"]
    assert loc.startswith("https://auth.kituwa.com/")
    assert "client_id=client-1" in loc and "code_challenge_method=S256" in loc


def test_callback_without_flow_is_rejected(client):
    assert client.get("/admin/oidc/callback?code=x&state=y").status_code == 400


def _member_app(tmp_path, monkeypatch, email="owner@kituwa.com"):
    from app.config import Settings
    from app.httpd import create_app
    settings = Settings(data_dir=tmp_path, secret=b"test-secret",
                        base_url="https://links.kituwa.com",
                        member_client_id="member-1", member_client_secret="s3cret")
    app = create_app(settings)
    monkeypatch.setattr("app.oidc.begin", lambda *a, **k: {
        "url": "https://auth.kituwa.com/authorize?client_id=member-1&state=s1",
        "state": "s1", "nonce": "n1", "verifier": "v1",
        "token_endpoint": "https://auth.kituwa.com/api/oidc/token"})
    monkeypatch.setattr("app.oidc.exchange", lambda *a, **k: {"id_token": "t"})
    monkeypatch.setattr("app.oidc.jwks", lambda *a, **k: {})
    monkeypatch.setattr("app.oidc.verify_id_token",
                        lambda *a, **k: {"sub": "u1", "email": email, "groups": ["members"]})
    return app, settings


def test_member_signin_provisions_account_and_session(tmp_path, monkeypatch):
    app, settings = _member_app(tmp_path, monkeypatch)
    client = app.test_client()
    assert client.get("/auth/pocketid").status_code == 302
    r = client.get("/auth/pocketid/callback?code=abc&state=s1")
    assert r.status_code == 302 and r.headers["Location"].endswith("/app")
    # the dashboard now renders for that account
    dash = client.get("/app")
    assert dash.status_code == 200 and "Your links" in dash.get_data(as_text=True)
    from app import db as dbmod
    conn = dbmod.connect(dbmod.db_path(settings.data_dir))
    row = conn.execute("SELECT * FROM accounts WHERE email=?", ("owner@kituwa.com",)).fetchone()
    conn.close()
    assert row is not None and row["email_verified"] == 1
    assert row["pw_hash"] == "!pocketid"   # password login cannot work for this account


def test_member_callback_rejects_bad_state(tmp_path, monkeypatch):
    app, _ = _member_app(tmp_path, monkeypatch)
    client = app.test_client()
    client.get("/auth/pocketid")
    assert client.get("/auth/pocketid/callback?code=abc&state=wrong").status_code == 400


def test_member_signin_disabled_without_client(client):
    assert client.get("/auth/pocketid").status_code == 503
