"""Per-use premium charging for links.

The first links are free. Past the allowance, each new link is charged from the
customer's KituwaCoin balance through the central premium API. The reference is
generated before the call, so a retry never charges twice.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request


class PremiumError(RuntimeError):
    pass


def charge(api_url: str, token: str, site: str, email: str, cents: int, reference: str,
           memo: str = "") -> tuple[bool, dict]:
    """Return (ok, result). 402 means the balance is short; 403 means bad token."""
    if not api_url or not token:
        raise PremiumError("premium charging is not configured")
    body = json.dumps({
        "email": email,
        "cents": int(cents),
        "reference": reference,
        "memo": memo[:200],
    }).encode()
    req = urllib.request.Request(
        api_url.rstrip("/") + "/api/premium/charge",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Kituwa-Site": site,
            "X-Kituwa-Token": token,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return True, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read() or b"{}")
        except ValueError:
            payload = {"error": f"premium API returned {exc.code}"}
        return False, payload
    except Exception as exc:  # noqa: BLE001
        raise PremiumError(f"premium API unreachable: {type(exc).__name__}") from exc
