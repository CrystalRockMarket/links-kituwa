import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import db as dbmod  # noqa: E402
from app.config import Settings  # noqa: E402
from app.httpd import create_app  # noqa: E402

CSRF_RE = re.compile(r'name="csrf" value="([^"]+)"')


@pytest.fixture()
def settings(tmp_path):
    return Settings(
        data_dir=tmp_path,
        secret=b"test-secret-key-not-for-production",
        base_url="http://127.0.0.1:8848",
        cookie_secure=False,
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


def csrf(html: str) -> str:
    m = CSRF_RE.search(html)
    assert m, "no csrf field in page"
    return m.group(1)


def make_account(conn, email="owner@example.com", password="correct horse battery") -> int:
    from app import security
    cur = conn.execute(
        "INSERT INTO accounts(email, pw_hash, created_at, email_verified, notify_email) VALUES (?,?,?,1,?)",
        (email, security.hash_password(password), security.utcnow(), email),
    )
    return int(cur.lastrowid)


def signin(client, email="owner@example.com", password="correct horse battery"):
    page = client.get("/login")
    r = client.post("/login", data={"csrf": csrf(page.get_data(as_text=True)),
                                    "email": email, "password": password})
    assert r.status_code in (302, 303), r.get_data(as_text=True)[:400]
    return r
