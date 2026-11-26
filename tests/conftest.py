import base64
import os
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import db as dbmod  # noqa: E402
from app.config import Settings  # noqa: E402
from app.httpd import create_app  # noqa: E402


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@pytest.fixture()
def settings(tmp_path):
    return Settings(
        data_dir=tmp_path,
        secret=b"test-secret-key-not-for-production",
        base_url="http://127.0.0.1:8891",
        cookie_secure=False,
        sweep=False,
        pow=False,
    )


@pytest.fixture()
def app(settings):
    application = create_app(settings)
    application.config.update(TESTING=True)
    return application


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def conn(settings):
    dbmod.init_db(dbmod.db_path(settings.data_dir))
    c = dbmod.connect(dbmod.db_path(settings.data_dir))
    yield c
    c.close()


def make_link(client, *, ciphertext=None, iv=None, salt=None, kdf="none",
              options=None, raw=False):
    body = {
        "ciphertext": b64(ciphertext if ciphertext is not None else os.urandom(48)),
        "iv": b64(iv if iv is not None else os.urandom(12)),
        "kdf": kdf,
        "options": options if options is not None else {"max_uses": 1, "expires_in": 3600},
    }
    if salt is not None:
        body["salt"] = b64(salt)
    resp = client.post("/api/links", json=body)
    assert resp.status_code == 201, resp.data
    return resp.get_json() if raw else resp
