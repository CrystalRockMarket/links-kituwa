#!/usr/bin/env python3
"""Staged Pocket ID diagnostics for links.kituwa.com (protocol 46).

Each stage prints one line: PASS / FAIL / SKIP / WARN, the endpoint, the HTTP
status and the content type or exception. A failure names its stage instead of
surfacing as "server error".

    python3 tools/sso_check.py                     # against the live site
    python3 tools/sso_check.py --base http://127.0.0.1:8891 --internal http://127.0.0.1:1411
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

UA = "Mozilla/5.0 (X11; Linux x86_64) links-sso-check/1.0"
results: list[tuple[str, str, str]] = []


def record(stage: str, state: str, detail: str) -> None:
    results.append((stage, state, detail))
    print(f"{state:4} {stage:10} {detail}")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def get(url: str, timeout: int = 12, headers: dict | None = None, follow: bool = True):
    opener = urllib.request.build_opener() if follow else urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    try:
        with opener.open(req, timeout=timeout) as r:  # noqa: S310
            return r.status, r.headers.get("Content-Type", ""), r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Content-Type", ""), e.read(), dict(e.headers)


def post(url: str, data: dict, timeout: int = 12):
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, headers={
        "User-Agent": UA,
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
            return r.status, r.headers.get("Content-Type", ""), r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Content-Type", ""), e.read()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="https://links.kituwa.com")
    ap.add_argument("--internal", default="", help="provider loopback base, e.g. http://127.0.0.1:1411")
    ap.add_argument("--issuer", default="https://auth.kituwa.com")
    ap.add_argument("--client-id", required=True)
    ap.add_argument("--secret-file", default="")
    args = ap.parse_args()

    provider = (args.internal or args.issuer).rstrip("/")

    # 1. discovery
    try:
        status, ctype, body, _ = get(provider + "/.well-known/openid-configuration")
        meta = json.loads(body) if "json" in ctype else {}
        if status == 200 and meta.get("token_endpoint"):
            record("discovery", "PASS", f"{status} {ctype.split(';')[0]} issuer={meta.get('issuer')}")
        else:
            record("discovery", "FAIL", f"{status} {ctype or 'no content-type'} — not a metadata document")
            return 1
    except Exception as exc:  # noqa: BLE001
        record("discovery", "FAIL", f"{type(exc).__name__}: {exc}")
        return 1

    # 2. authorize (browser-facing URL must be on the public issuer)
    auth = meta["authorization_endpoint"]
    q = urllib.parse.urlencode({
        "response_type": "code", "client_id": args.client_id,
        "redirect_uri": args.base + "/auth/pocketid/callback",
        "scope": "openid email groups",
        "state": secrets.token_urlsafe(24), "nonce": secrets.token_urlsafe(24),
        "code_challenge": base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("="),
        "code_challenge_method": "S256",
    })
    status, ctype, body, headers = get(auth + "?" + q, follow=False)
    if status in (200, 302) and "html" in (ctype or ""):
        record("authorize", "PASS", f"{status} {ctype.split(';')[0]} {auth}")
    else:
        record("authorize", "FAIL", f"{status} {ctype or 'no content-type'} {auth}")

    # 3. token — a bogus code must answer JSON, not an HTML 404
    status, ctype, body = post(meta["token_endpoint"], {
        "grant_type": "authorization_code", "code": "bogus-code-for-diagnostics",
        "redirect_uri": args.base + "/auth/pocketid/callback", "client_id": args.client_id,
        "client_secret": "bogus", "code_verifier": "a" * 43,
    })
    try:
        err = json.loads(body).get("error", "")
    except Exception:  # noqa: BLE001
        err = ""
    if "json" in (ctype or "") and status in (400, 401) and err:
        record("token", "PASS", f"{status} {ctype.split(';')[0]} error={err} (endpoint answers JSON)")
    elif "json" in (ctype or ""):
        record("token", "WARN", f"{status} {ctype.split(';')[0]} no error body")
    else:
        record("token", "FAIL", f"{status} {ctype or 'no content-type'} — HTML here means a wrong path")

    # 4. userinfo
    ui = meta.get("userinfo_endpoint")
    if ui:
        status, ctype, body, _ = get(ui)
        state = "PASS" if status in (401, 403) else "WARN"
        record("userinfo", state, f"{status} {ctype.split(';')[0]} (401/403 expected without a token)")
    else:
        record("userinfo", "SKIP", "provider advertises no userinfo endpoint")

    # 5. callback / session / landing on our own site
    status, ctype, body, _ = get(args.base + "/auth/pocketid/callback?code=x&state=y")
    record("callback", "PASS" if status == 400 else "FAIL", f"{status} {ctype.split(';')[0]} (400 without a flow is correct)")

    status, ctype, body, headers = get(args.base + "/auth/pocketid", follow=False)
    loc = headers.get("Location", "")
    if status == 302 and "client_id=" + args.client_id in loc and "code_challenge_method=S256" in loc:
        record("session", "PASS", f"302 authorize with client {args.client_id[:8]}… and PKCE S256")
    else:
        record("session", "FAIL", f"{status} location={loc[:80] or 'none'}")

    status, ctype, body, _ = get(args.base + "/healthz")
    record("landing", "PASS" if status == 200 else "FAIL", f"{status} {ctype.split(';')[0]}")

    failed = [s for s, st, _ in results if st == "FAIL"]
    print(f"\n{len(results) - len(failed)}/{len(results)} stages ok"
          + (f" — failing: {', '.join(failed)}" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
