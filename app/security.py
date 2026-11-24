"""Passwords, sessions, CSRF, request identity and target-URL validation."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def iso_after(days: int = 0, minutes: int = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days, minutes=minutes)) \
        .replace(microsecond=0).isoformat()


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


# --- link codes ------------------------------------------------------------
# Crockford-ish alphabet: no vowels, no look-alike pairs (0/O, 1/l/I).
ALPHABET = "23456789abcdefghjkmnpqrstuvwxyz"
CODE_LEN = 8


def new_code() -> str:
    return "".join(secrets.choice(ALPHABET) for _ in range(CODE_LEN))


CODE_RE = re.compile(r"^[%s]{%d}$" % (ALPHABET, CODE_LEN))


def valid_code(code: str) -> bool:
    return bool(CODE_RE.match(code or ""))


# --- target URL ------------------------------------------------------------
_BLOCKED_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}


def normalise_target(raw: str) -> str | None:
    """Return a safe absolute http(s) URL, or None.

    Rejects credentials in the URL, non-http schemes (javascript:, data:, file:),
    control characters and over-long input. Short links may point anywhere on
    the public web; they may not be used as an open redirect into a scheme the
    browser executes.
    """
    raw = (raw or "").strip()
    if not raw or len(raw) > 2048 or any(ord(c) < 32 for c in raw):
        return None
    if "://" not in raw:
        # Reject things like "javascript:alert(1)" that only look like a URL.
        head = raw.split("/", 1)[0]
        if ":" in head and not head.split(":")[0].isdigit():
            return None
        raw = "https://" + raw
    try:
        parts = urlsplit(raw)
    except ValueError:
        return None
    if parts.scheme not in {"http", "https"}:
        return None
    if not parts.hostname or "@" in parts.netloc:
        return None
    if parts.hostname.strip("[]").lower() in _BLOCKED_HOSTS:
        return None
    if any(ch in raw for ch in "\r\n\t \"<>"):
        return None
    return parts.geturl()


# --- client identity -------------------------------------------------------
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


def store_ip(ip: str, mode: str) -> str:
    """Retain what the operator asked for, with an explicit privacy switch."""
    if not ip:
        return ""
    if mode == "hashed":
        return hashlib.sha256(ip.encode()).hexdigest()[:24]
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    if mode == "truncated":
        if addr.version == 4:
            return str(ipaddress.ip_network(f"{addr}/24", strict=False).network_address) + "/24"
        return str(ipaddress.ip_network(f"{addr}/48", strict=False).network_address) + "/48"
    return str(addr)


def fingerprint(secret: bytes, ip: str, ua: str, lang: str) -> str:
    """Stable per-browser signal for 'a new person opened this link'."""
    mac = hmac.new(secret, digestmod=hashlib.sha256)
    mac.update((ip or "").encode())
    mac.update(b"\0")
    mac.update((ua or "").encode())
    mac.update(b"\0")
    mac.update((lang or "").encode())
    return mac.hexdigest()[:32]


# --- share vs preview ------------------------------------------------------
_BOT_RE = re.compile(
    r"(bot|crawler|spider|slurp|facebookexternalhit|whatsapp|telegrambot|slackbot|"
    r"discordbot|twitterbot|linkedinbot|pinterest|skypeuripreview|embedly|"
    r"headlesschrome|python-requests|curl/|wget/|go-http-client|preview)",
    re.IGNORECASE,
)


def is_preview(ua: str, purpose: str) -> bool:
    """Link unfurlers must never burn a one-time link."""
    purpose = (purpose or "").lower()
    if any(tag in purpose for tag in ("prefetch", "prerender", "preview")):
        return True
    return bool(_BOT_RE.search(ua or ""))


SHARE_HOSTS = (
    "mail.", "gmail.", "outlook.", "yahoo.", "proton.", "whatsapp.", "web.whatsapp.",
    "t.me", "telegram.", "discord.", "slack.", "facebook.", "fb.", "m.me",
    "instagram.", "twitter.", "x.com", "t.co", "linkedin.", "reddit.", "signal.",
)


def referer_is_share(referer: str) -> bool:
    """A referrer from a messaging/mail surface means the link was forwarded."""
    if not referer:
        return False
    try:
        host = (urlsplit(referer).hostname or "").lower()
    except ValueError:
        return False
    return any(host == h.rstrip(".") or host.startswith(h) for h in SHARE_HOSTS)
