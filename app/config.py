"""Runtime configuration for Secret Link.

Everything is environment driven so the same tree runs in development, in the
test suite and behind the published host. No secret is ever committed: the
session/fingerprint key is generated on first use at ``$SL_DATA_DIR/secret.key``
with mode 0600.
"""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, replace
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    secret: bytes
    host: str = "127.0.0.1"
    port: int = 8848
    base_url: str = "https://links.kituwa.com"
    cookie_secure: bool = False
    ip_mode: str = "full"          # full | truncated | hashed
    session_days: int = 30
    max_body: int = 64 * 1024
    smtp_host: str | None = None
    mail_from: str = "Secret Link <links@kituwa.com>"
    allow_signup: bool = True

    def with_base(self, base_url: str) -> "Settings":
        return replace(self, base_url=base_url.rstrip("/"))


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _load_secret(data_dir: Path) -> bytes:
    key_path = data_dir / "secret.key"
    if key_path.exists():
        return key_path.read_bytes().strip()
    data_dir.mkdir(parents=True, exist_ok=True)
    key = secrets.token_hex(32).encode()
    key_path.write_bytes(key + b"\n")
    key_path.chmod(0o600)
    return key


def load_settings() -> Settings:
    data_dir = Path(os.environ.get("SL_DATA_DIR", PROJECT_ROOT / "data")).resolve()
    data_dir.mkdir(parents=True, exist_ok=True)
    ip_mode = os.environ.get("SL_IP_MODE", "full").strip().lower()
    if ip_mode not in {"full", "truncated", "hashed"}:
        raise SystemExit(f"SL_IP_MODE must be full|truncated|hashed, got {ip_mode!r}")
    base_url = os.environ.get("SL_BASE_URL", "https://links.kituwa.com").rstrip("/")
    return Settings(
        data_dir=data_dir,
        secret=_load_secret(data_dir),
        host=os.environ.get("SL_HOST", "127.0.0.1"),
        port=int(os.environ.get("SL_PORT", "8848")),
        base_url=base_url,
        cookie_secure=_bool("SL_COOKIE_SECURE", base_url.startswith("https://")),
        ip_mode=ip_mode,
        session_days=int(os.environ.get("SL_SESSION_DAYS", "30")),
        smtp_host=os.environ.get("SL_SMTP_HOST") or None,
        mail_from=os.environ.get("SL_MAIL_FROM", "Secret Link <links@kituwa.com>"),
        allow_signup=_bool("SL_ALLOW_SIGNUP", True),
    )
