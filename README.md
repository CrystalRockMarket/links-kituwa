# Secret Link

Short links that stop working by design. A link is created with a budget of
opens — one by default — and answers `410 Gone` the moment the budget is spent.
Unlimited links are supported for pure tracking. Every open, device, referrer,
IP and pass-along is recorded for the link's owner.

- **Status:** implemented and tested locally; **not launched, not registered,
  no DNS record yet**.
- **Planned name:** `secret-link.kituwa.com` (decision pending, see
  `docs/PLAN.md`).

## What it does

| Behaviour | Default | Notes |
| --- | --- | --- |
| Uses per link | **1** | "One-time" destroys itself on first open |
| Budgeted uses | 2–100000 | Exactly N opens; the counter is transactional |
| Unlimited | optional | `mode = track`, tracking only, never closes |
| Expiry | never | optional 1/7/30 days |
| Preview fetches | never counted | Facebook/WhatsApp/Telegram/Slack/Discord/Slack/HEAD/prefetch |
| Open log | on | time, stored IP, user agent, referrer, pass-along token |
| New-device alert | on | a second device on a multi-use link |
| Forward alert | on | mail/messaging referrer, or an attributed pass-along open |
| Manual controls | on | destroy now, pause, resume |

## How "who shared it with who" is represented

A short link is anonymous: a recipient has no name until they identify
themselves. The system records three honest signals instead of inventing an
identity:

1. **Device** — a keyed HMAC of IP + UA + Accept-Language. A second device on a
   budgeted link raises `new_visitor`.
2. **Referrer** — a mail or messaging host in the `Referer` header raises
   `shared`, with the host preserved.
3. **Pass-along token** — a recipient can mint `…/s/<code>?via=<token>`; each
   token belongs to the visitor who created it, and every open through it is
   attributed and alerted.

## Why a preview must not burn a one-time link

Messengers unfurl a URL before a human sees it. If that fetch consumed the only
use, the recipient would get a dead link. Preview user agents and
`Sec-Purpose: prefetch|prerender` receive an interstitial and are logged as
`kind = preview`; only the human "Continue" click (`?go=1`) consumes.

## Run it

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
SL_DATA_DIR=/tmp/sl SL_BASE_URL=http://127.0.0.1:8848 .venv/bin/python run.py --port 8848
```

Environment: `SL_DATA_DIR`, `SL_BASE_URL`, `SL_HOST`, `SL_PORT`,
`SL_COOKIE_SECURE`, `SL_IP_MODE` (`full|truncated|hashed`), `SL_SESSION_DAYS`,
`SL_SMTP_HOST`, `SL_MAIL_FROM`, `SL_ALLOW_SIGNUP`.

Mail with no SMTP host is written to `$SL_DATA_DIR/outbox/*.eml` so
verification links are inspectable without pretending they were delivered.

## Verify

```bash
.venv/bin/python -m pytest -q          # 27 passed
tools/smoke.sh http://127.0.0.1:8851   # end-to-end, prints each step
```

`pytest` proves the destructive contract, including a 10-thread race against a
3-use link that yields exactly 3 successes. `tools/smoke.sh` walks signup →
verify → login → create → open twice → preview-not-counted against a live
server.

## Security notes

- argon2id passwords, 12-character minimum, login throttled per email+IP.
- Session cookies `HttpOnly`, `SameSite=Lax`, `Secure` when the base URL is
  https; CSRF token on every state-changing form.
- `CSP`, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: same-origin`;
  link responses are `Cache-Control: no-store`.
- Destinations are restricted to `http(s)`; `javascript:`, `data:`, `file:`,
  credentials-in-URL and control characters are rejected.
- Object-scoped access: a link detail page is only reachable by its owner.
- IP storage is a policy choice, not an accident — set `SL_IP_MODE`.

## Not built yet

Pocket ID operator client, the public host deployment, DNS, directory
registration (Hub/Portfolio/Start/Atlas/watchdog), work log and backup. See
`docs/PLAN.md`.
