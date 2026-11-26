# Decisions — 2026-11-26 cutover

Owner instruction: *"remove all data tracked for users who click the link. Do
not store any user data about link click origins. Use E2EE to make link sharing
as secure as possible."*

## What changed

| Before | After |
| --- | --- |
| Destination stored in plaintext | AES-256-GCM ciphertext, key only in the URL fragment |
| Per-click log: IP, UA, referrer, device HMAC | Nothing. No table, no column, no log line |
| Unlimited "tracking" links with alerts | Gone. A link is a budget and a clock |
| Accounts required, 1¢ per link past 25 | No accounts, no charge, no account table |
| GET /<code> consumed a use | `GET /l/<id>` spends nothing; only a click consumes |
| Expired rows kept forever | Ciphertext wiped at 0 uses or expiry; row deleted after 7 days |
| nginx access log on | `access_log off` for the whole vhost |
| Network bar on every page | Bar on public pages; none on `/l/*` or `/m/*` |

## Answered by the owner

1. **Existing data** — purge click history now. Done at cutover; `opens`,
   `visitors`, `share_tokens` and `alerts` are dropped and the database is
   vacuumed. On 2026-11-26 the owner confirmed nobody else had used the site, so
   the legacy link table and the account tables were removed as well.
2. **Public repository** — `github.com/CrystalRockMarket/links-kituwa`, public.
3. **Accounts and price** — anonymous creation, no charge. The account system
   was removed entirely on 2026-11-26; only the operator console remains.

## Deliberate deviations

- **Protocol 1 rule 3 / network bar.** The bar is absent from `/l/*` and
  `/m/*`. A third-party script on the decrypt page could read the key from
  `location.hash`, which would defeat the whole design. The owner's prompt
  requires the exception explicitly; recorded here per protocol 18.
- **The host runs the app.** A shortener must answer every request, so it cannot
  be a static artifact on the host. The host serves; the worker builds, signs and
  publishes. Recorded per Protocol 1 rule 7.

## Not in this increment

- QR code generation (needs a vendored encoder; Web Crypto does not provide one).
- Creator webhook/ntfy notification on open (deliberately omitted: it would make
  the server contact a third party on every open).
- Multi-device manage tokens (one token per link, as specified).
