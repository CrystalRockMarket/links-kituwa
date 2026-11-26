"""Operator console sign-in (Pocket ID). There are no consumer accounts."""
import pytest

from app import db as dbmod


def test_admin_requires_sign_in(client):
    r = client.get("/admin")
    assert r.status_code == 302 and "/admin/login" in r.headers["Location"]


def test_admin_login_redirects_to_the_provider(tmp_path, monkeypatch):
    from app.config import Settings
    from app.httpd import create_app

    settings = Settings(data_dir=tmp_path, secret=b"test-secret",
                        base_url="https://links.kituwa.com", oidc_client_id="client-1")
    app = create_app(settings)
    monkeypatch.setattr("app.oidc.begin", lambda *a, **k: {
        "url": "https://auth.kituwa.com/authorize?client_id=client-1&state=s1"
               "&code_challenge=abc&code_challenge_method=S256&nonce=n1",
        "state": "s1", "nonce": "n1", "verifier": "v1",
        "token_endpoint": "https://auth.kituwa.com/api/oidc/token"})
    client = app.test_client()
    r = client.get("/admin/login")
    assert r.status_code == 302
    loc = r.headers["Location"]
    assert loc.startswith("https://auth.kituwa.com/")
    assert "client_id=client-1" in loc and "code_challenge_method=S256" in loc


def test_callback_without_flow_is_rejected(client):
    assert client.get("/admin/oidc/callback?code=x&state=y").status_code == 400


def test_admin_callback_requires_the_operators_group(tmp_path, monkeypatch):
    from app.config import Settings
    from app.httpd import create_app

    settings = Settings(data_dir=tmp_path, secret=b"test-secret",
                        base_url="https://links.kituwa.com",
                        oidc_client_id="client-1", oidc_client_secret="s3cret")
    app = create_app(settings)
    monkeypatch.setattr("app.oidc.begin", lambda *a, **k: {
        "url": "https://auth.kituwa.com/authorize?state=s1", "state": "s1",
        "nonce": "n1", "verifier": "v1",
        "token_endpoint": "https://auth.kituwa.com/api/oidc/token"})
    monkeypatch.setattr("app.oidc.exchange", lambda *a, **k: {"id_token": "t"})
    monkeypatch.setattr("app.oidc.jwks", lambda *a, **k: {})
    monkeypatch.setattr("app.oidc.verify_id_token",
                        lambda *a, **k: {"sub": "u1", "email": "m@kituwa.com",
                                         "groups": ["members"]})
    client = app.test_client()
    client.get("/admin/login")
    r = client.get("/admin/oidc/callback?code=abc&state=s1")
    assert r.status_code == 403
    assert b"not in the operators group" in r.data

    # the same identity in the operators group is admitted
    monkeypatch.setattr("app.oidc.verify_id_token",
                        lambda *a, **k: {"sub": "u1", "email": "m@kituwa.com",
                                         "groups": ["operators"]})
    client.get("/admin/login")
    r = client.get("/admin/oidc/callback?code=abc&state=s1")
    assert r.status_code == 302 and r.headers["Location"].endswith("/admin")
    assert client.get("/admin").status_code == 200


def test_admin_login_disabled_without_client(client):
    assert client.get("/admin/login").status_code == 503
