"""Per-click insight for the owner's Details panel.

Everything here is derived locally and offline: the IP never leaves the host.
Geo comes from a DB-IP Lite city database shipped with the service; the user
agent is parsed by hand so no third-party library is needed.
"""

from __future__ import annotations

import os
import re
from functools import lru_cache
from pathlib import Path

MMDB_PATH = Path(os.environ.get("SECRET_LINK_GEO_DB", "data/geo/dbip-city-lite.mmdb"))

# Bots worth naming: preview fetchers, crawlers, link scanners.
_BOT_PATTERNS = [
    (re.compile(r"facebookexternalhit", re.I), "Facebook preview"),
    (re.compile(r"WhatsApp", re.I), "WhatsApp preview"),
    (re.compile(r"Twitterbot", re.I), "X/Twitter preview"),
    (re.compile(r"LinkedInBot", re.I), "LinkedIn preview"),
    (re.compile(r"Slackbot|Slack-ImgProxy", re.I), "Slack preview"),
    (re.compile(r"TelegramBot", re.I), "Telegram preview"),
    (re.compile(r"Discordbot", re.I), "Discord preview"),
    (re.compile(r"Googlebot", re.I), "Googlebot"),
    (re.compile(r"bingbot", re.I), "Bingbot"),
    (re.compile(r"bot\b|crawler|spider|preview", re.I), "Bot"),
]


def _browser(ua: str) -> str:
    for needle, name in (
        ("Edg/", "Edge"), ("OPR/", "Opera"), ("Chrome/", "Chrome"),
        ("Firefox/", "Firefox"), ("Safari/", "Safari"),
    ):
        if needle in ua:
            return name
    return "Unknown"


def _os(ua: str) -> str:
    for needle, name in (
        ("iPhone", "iOS"), ("iPad", "iPadOS"), ("Android", "Android"),
        ("Windows NT", "Windows"), ("Mac OS X", "macOS"), ("CrOS", "ChromeOS"),
        ("Linux", "Linux"),
    ):
        if needle in ua:
            return name
    return "Unknown"


def _device(ua: str) -> str:
    if re.search(r"iPad|Tablet", ua):
        return "tablet"
    if re.search(r"Mobi|iPhone|Android.*Mobile", ua):
        return "phone"
    if ua:
        return "desktop"
    return "unknown"


def parse_ua(ua: str | None) -> dict:
    ua = ua or ""
    bot = next((name for rx, name in _BOT_PATTERNS if rx.search(ua)), None)
    return {
        "bot": bot,
        "browser": None if bot else _browser(ua),
        "os": None if bot else _os(ua),
        "device": "bot" if bot else _device(ua),
    }


@lru_cache(maxsize=1)
def _reader():
    try:
        import maxminddb  # noqa: PLC0415
    except Exception:  # pragma: no cover - optional dependency
        return None
    try:
        return maxminddb.open_database(str(MMDB_PATH))
    except Exception:
        return None


def geo(ip: str | None) -> dict:
    """Country/region/city for an address, or an empty dict when unknown."""
    if not ip:
        return {}
    reader = _reader()
    if reader is None:
        return {}
    try:
        rec = reader.get(ip) or {}
    except Exception:
        return {}
    if not rec:
        return {}
    country = rec.get("country") or {}
    names = country.get("names") or {}
    subs = rec.get("subdivisions") or []
    cities = rec.get("city") or {}
    return {
        "country": names.get("en") or country.get("iso_code"),
        "country_code": country.get("iso_code"),
        "region": ((subs[0].get("names") or {}).get("en") if subs else None),
        "city": (cities.get("names") or {}).get("en"),
        "lat": (rec.get("location") or {}).get("latitude"),
        "lon": (rec.get("location") or {}).get("longitude"),
    }


def describe(ip: str | None, ua: str | None) -> dict:
    """Everything we can honestly say about one click."""
    out = {"ip": ip}
    out.update(geo(ip))
    out.update(parse_ua(ua))
    return out
