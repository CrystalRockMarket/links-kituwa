"""In-memory rate limiting and a self-hosted proof-of-work challenge.

Nothing here is written to disk. The bucket key is an HMAC of the client
address, kept only for the life of the process, so a restart forgets everyone.

The proof-of-work is a small, dependency-free CAPTCHA replacement: the server
signs a challenge, the browser finds a nonce whose SHA-256 has a number of
leading zero bits, and the server checks it statelessly. No third party, no
image puzzle, no Google.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from collections import defaultdict, deque

DEFAULT_LIMITS = {
    "create": (30, 3600),      # 30 links per hour per client
    "consume": (600, 3600),    # 600 opens per hour per client (shared NATs)
    "report": (5, 3600),
    "manage": (60, 3600),
    "login": (20, 900),
}

POW_BITS = 20
POW_MAX_AGE = 300
PRESSURE_WINDOW = 60
PRESSURE_LIMIT = 30


class Limiter:
    def __init__(self, limits: dict[str, tuple[int, int]] | None = None) -> None:
        self._limits = dict(limits or DEFAULT_LIMITS)
        self._hits: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._recent_creates: deque[float] = deque()

    def allow(self, kind: str, key: str) -> bool:
        limit, window = self._limits.get(kind, (60, 3600))
        now = time.monotonic()
        with self._lock:
            q = self._hits[(kind, key)]
            while q and q[0] < now - window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            if kind == "create":
                self._recent_creates.append(now)
                while self._recent_creates and self._recent_creates[0] < now - PRESSURE_WINDOW:
                    self._recent_creates.popleft()
            return True

    def under_pressure(self) -> bool:
        with self._lock:
            return len(self._recent_creates) >= PRESSURE_LIMIT

    def prune(self) -> None:
        """Drop empty buckets so memory does not grow without bound."""
        now = time.monotonic()
        with self._lock:
            for key in [k for k, q in self._hits.items()
                        if not q or q[-1] < now - 86400]:
                self._hits.pop(key, None)


def _mac(secret: bytes, body: str) -> str:
    return hmac.new(secret, body.encode(), hashlib.sha256).hexdigest()[:24]


def challenge(secret: bytes, bits: int = POW_BITS) -> dict:
    ts = str(int(time.time()))
    nonce = secrets.token_hex(8)
    body = f"{ts}.{nonce}.{bits}"
    return {"challenge": f"{body}.{_mac(secret, body)}", "bits": bits}


def _leading_zero_bits(digest: bytes) -> int:
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
            continue
        bits += 8 - byte.bit_length()
        break
    return bits


def verify(secret: bytes, token: str, solution: str, bits: int | None = None) -> bool:
    try:
        ts, nonce, claimed, mac = (token or "").split(".")
        claimed_bits = int(claimed)
    except (ValueError, AttributeError):
        return False
    if bits is not None and claimed_bits != bits:
        return False
    if not (1 <= claimed_bits <= 28):
        return False
    if not hmac.compare_digest(mac, _mac(secret, f"{ts}.{nonce}.{claimed}")):
        return False
    try:
        if abs(time.time() - int(ts)) > POW_MAX_AGE:
            return False
    except ValueError:
        return False
    try:
        n = int(solution)
    except (TypeError, ValueError):
        return False
    digest = hashlib.sha256(f"{token}:{n}".encode()).digest()
    return _leading_zero_bits(digest) >= claimed_bits


__all__ = ["Limiter", "challenge", "verify", "POW_BITS", "POW_MAX_AGE"]
