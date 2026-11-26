"""Passwords, sessions, tokens, and the little identity the server still needs.

There is deliberately no ``fingerprint()``, ``store_ip()`` or referrer parsing
here any more. The service does not build a picture of a clicker. The only
client-derived value in the process is a short-lived HMAC used as an in-memory
rate-limit bucket key, and it is never written anywhere.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import secrets
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def iso_after(days: int = 0, minutes: int = 0, seconds: int = 0) -> str:
    return (datetime.now(timezone.utc)
            + timedelta(days=days, minutes=minutes, seconds=seconds)) \
        .replace(microsecond=0).isoformat()


def iso_from(stamp: str, seconds: int = 0) -> str:
    """Add seconds to an ISO timestamp, normalising to UTC with no microseconds."""
    try:
        base = datetime.fromisoformat(stamp)
    except (TypeError, ValueError):
        base = datetime.now(timezone.utc)
    if base.tzinfo is None:
        base = base.replace(tzinfo=timezone.utc)
    return (base + timedelta(seconds=seconds)).replace(microsecond=0).isoformat()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(pw_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(pw_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def needs_rehash(pw_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(pw_hash)
    except InvalidHashError:
        return True


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# --- link ids --------------------------------------------------------------
# 16 random bytes, base64url, no padding: 22 characters, 128 bits.
ID_RE = re.compile(r"^[A-Za-z0-9_-]{22}$")


def valid_id(link_id: str) -> bool:
    return bool(ID_RE.match(link_id or ""))


# --- legacy codes ----------------------------------------------------------
ALPHABET = "23456789abcdefghjkmnpqrstuvwxyz"
CODE_LEN = 8
CODE_RE = re.compile(r"^[%s]{%d}$" % (ALPHABET, CODE_LEN))


def valid_code(code: str) -> bool:
    return bool(CODE_RE.match(code or ""))


# --- client address, used only to bucket rate limits ----------------------

def client_ip(remote_addr: str | None, forwarded_for: str | None) -> str:
    """Take the first hop of X-Forwarded-For only when it parses as an IP."""
    if forwarded_for:
        first = forwarded_for.split(",")[0].strip()
        try:
            return str(ipaddress.ip_address(first))
        except ValueError:
            pass
    try:
        return str(ipaddress.ip_address((remote_addr or "").strip()))
    except ValueError:
        return ""


def bucket(secret: bytes, ip: str) -> str:
    """An HMAC of the address for in-memory rate limiting. Never persisted."""
    return hmac.new(secret, (ip or "").encode(), hashlib.sha256).hexdigest()[:24]


# --- messenger previews (legacy links only) -------------------------------
# A preview fetch must not spend the last use of a link that is already in the
# wild. This reads the request headers in memory; nothing is stored.
_BOT_RE = re.compile(
    r"(bot|crawler|spider|slurp|facebookexternalhit|whatsapp|telegrambot|slackbot|"
    r"discordbot|twitterbot|linkedinbot|pinterest|skypeuripreview|embedly|"
    r"headlesschrome|python-requests|curl/|wget/|go-http-client|preview)",
    re.IGNORECASE,
)


def is_preview(ua: str, purpose: str) -> bool:
    purpose = (purpose or "").lower()
    if any(tag in purpose for tag in ("prefetch", "prerender", "preview")):
        return True
    return bool(_BOT_RE.search(ua or ""))
