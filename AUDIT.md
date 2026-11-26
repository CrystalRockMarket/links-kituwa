# AUDIT — links.kituwa.com (secret-link-kituwa)

> **Superseded on 2026-11-26.** This audit describes the service before the
> zero-knowledge cutover. The plaintext `target` column, the click tables, the
> account tables and the legacy link table have all been removed; the running
> schema is `links` and `reports` only. `docs/PLAN.md` records the decisions and
> `README.md` describes the current design.

Audit date: 2026-11-26. Pack 2.28.0. Protocols applied: 01, 03, 05, 08, 10, 13,
16, 18, 21, 23, 29, 40, plus Protocol 1.

This audit describes the service **as deployed at 2026-11-26 14:16 UTC**, before
the zero-knowledge rebuild. It is the baseline the migration is measured
against.

## 1. Stack

| Layer | What runs |
| --- | --- |
| Runtime | Python 3.12, Flask 3.1.3, waitress 3.0.2 (`run.py`, 8 threads) |
| Storage | SQLite, WAL, `isolation_level=None`, `BEGIN IMMEDIATE` for mutations |
| Templates | Jinja2 server-rendered HTML, no build step |
| Front end | Hand-written CSS/JS, no framework, no bundler |
| Crypto (server) | argon2-cffi (passwords), `cryptography` (OIDC JWT), `itsdangerous` (session) |
| Geo | `maxminddb` + DB-IP Lite city database at `data/geo/` |
| Host | `kituwa-cloud-1` (GCP), nginx 443 → `127.0.0.1:8891`, systemd unit `links-kituwa`, user `ubuntu` |
| TLS | Let's Encrypt, TLS 1.2/1.3, `server_tokens off` |
| Source of truth | trinity `~/projects/secret-link-kituwa`, rsync'd to `/home/ubuntu/services/links-kituwa` (the host copy is **not** a git checkout) |

## 2. Data model (current)

```
accounts(email, pw_hash, created_at, email_verified, default_uses, notify_email, alerts)
sessions(token_hash, account_id, csrf, created_at, expires_at)
links(id, account_id, code, target, label, max_uses, uses, mode,
      created_at, expires_at, destroyed_at, disabled_at)
visitors(id, link_id, fp, first_seen, opens, last_ip)
opens(id, link_id, visitor_id, ts, ip, ua, referer, via, kind)
share_tokens(token, link_id, visitor_id, created_at, opens)
alerts(id, account_id, link_id, kind, body, created_at, seen)
verify_tokens(token_hash, account_id, expires_at, used)
login_attempts(key = sha256(email):ip, fails, first_fail)
```

`visitors.fp` is `HMAC-SHA256(server_secret, ip || ua || accept-language)`, i.e. a
keyed device fingerprint. `opens` is a per-click record of time, **IP address**,
**user agent**, **Referer**, pass-along token and kind. The owner Details panel
additionally resolves the IP to country/region/city offline (`app/insight.py`).

## 3. Every place a plaintext destination URL lives or travels

| # | Location | Kind |
| --- | --- | --- |
| 1 | `links.target` column (SQLite + WAL + `-shm`) | stored |
| 2 | SQLite file on the host and in every backup/snapshot of `data/` | stored |
| 3 | `GET /app/link/<id>` → rendered `<p class="dest">{{ link['target'] }}</p>` | transmitted |
| 4 | `GET /app/link/<id>/clicks.json` → `"target": link["target"]` | transmitted (JSON) |
| 5 | `GET /<code>` → `302 Location: <target>` | transmitted to the clicker |
| 6 | `GET /s/<code>` → same | transmitted |
| 7 | `tracking.consume()` return value in process memory | in memory |
| 8 | nginx access log: request path only (`/<code>`), **not** the target | log (path only) |
| 9 | The owner's browser history / the destination's `Referer` (currently `same-origin`, so no referrer is sent cross-origin) | client |
| 10 | `links.label` — creator-supplied, often describes the destination | stored |

The server has always seen the destination. That is the property being removed.

## 4. Link creation and resolution (current)

- Creation: `POST /app/new`, account required, CSRF, optional 1¢ premium charge
  past 25 links (`app/premium.py`). `security.normalise_target()` validates
  http/https, rejects credentials-in-URL, control characters, `localhost`.
- Resolution: `GET /<code>` → `tracking.consume()`. It detects messenger
  previewers by User-Agent and `Sec-Purpose`, records a `preview` row, and does
  not spend a use. Otherwise it runs a guarded `UPDATE … WHERE uses < max_uses`
  inside `BEGIN IMMEDIATE`, records the open, upserts the visitor fingerprint,
  raises alerts, and returns a `302` straight to the destination.
- `mode='track'` links are unlimited and count every open.
- `POST /<code>/share` mints a pass-along token bound to the visitor fingerprint.

## 5. Use counts and expiry (current)

- Atomic: the check and the increment are one statement inside an immediate
  transaction. Concurrent opens cannot both pass.
- A budgeted link that reaches `max_uses` gets `destroyed_at` set; the row (and
  the plaintext target) remains in the database forever.
- Expiry is checked at read time only. There is no sweeper: expired rows and
  their targets persist indefinitely.
- `db.purge_ips()` nulls IPs older than 90 days at boot. Nothing else is purged.

## 6. Logging and retention (current)

| What | Where | Retention |
| --- | --- | --- |
| Client IP, path, status, UA, Referer | nginx `/var/log/nginx/access.log` (global `access_log`, no per-site override) | logrotate default |
| Client IP, UA, Referer, `via` | `opens` table | forever (IPs nulled after 90 d) |
| Device fingerprint | `visitors.fp` | forever |
| Geo (city/lat/lon) | derived on demand from IP | with the IP |
| Account email, password hash | `accounts` | forever |
| Session token hash | `sessions` | 30 days |
| Login failures keyed by email+IP | `login_attempts` | forever |

## 7. Third-party code and assets (current)

- `<kituwa-network>` bar: `https://hub.kituwa.com/network/…` on every public page
  (`base.html`, `recipient_base.html`), plus a watchdog link. This is the only
  third-party origin, and `connect-src`/`img-src` allow it.
- No web fonts, no CDN, no analytics, no chat widget, no Google reCAPTCHA.
- All CSS/JS is self-hosted under `app/static/`.
- **Gap:** the network bar is a third-party script on every page, including the
  page a recipient opens. Any script on that page can read `location.hash`.

## 8. Security headers (measured, 2026-11-26 14:16 UTC)

```
HTTP/2 200
server: nginx
content-security-policy: default-src 'self'; img-src 'self' data: https://hub.kituwa.com;
  style-src 'self'; script-src 'self'; connect-src 'self' https://hub.kituwa.com
  https://admin.kituwa.com https://id.kituwa.com; form-action 'self';
  frame-ancestors 'none'; base-uri 'none'
referrer-policy: same-origin
set-cookie: sl_sid=…; Secure; HttpOnly; Path=/; SameSite=Lax
x-content-type-options: nosniff
x-frame-options: DENY
strict-transport-security: max-age=31536000; includeSubDomains
```

Missing or wrong: HSTS lacks `preload` and the 2-year `max-age`; `Referrer-Policy`
should be `no-referrer`; no `Permissions-Policy`; no `Cross-Origin-Opener-Policy`;
no SRI on any script or stylesheet; a session cookie is set on **every** request,
including the open-link flow; nginx access logging is on for every path.

## 9. Defects found during the audit

1. **`POST /app/new` raises `NameError`** past the free allowance: `httpd.py`
   uses `premium_api` and `uuid4` without importing either (committed in
   `88ec894`). The charge path has never run.
2. **`GET` mutates state.** Opening a link consumes a use on a GET, so a
   prefetcher that does not match the bot regex burns the link. This is the
   exact failure the new design removes.
3. **No rate limiting** on creation or opening.
4. **No sweeper**: expired links and their plaintext targets never leave the DB.
5. **Session cookie on the open flow** (`session["anon_csrf"]` is written on
   every request) — a tracker and a cache-variance cost on `/l/*`.
6. **No `/privacy` page** (404), no `/robots.txt` (served the HTML shell).
7. **Host copy is not a git checkout**, so the running code cannot be tied to a
   commit or a hash. Nothing on the site states what it runs.
8. `insight.py` imports `maxminddb` lazily; the geo DB is present on the host and
   absent locally, so behaviour differs between environments.
9. The committed tree has `.bak-*` files and a modified `httpd.py` in flight from
   a network-bar migration; both must be reconciled before release.

## 10. Stack decision

**Keep the stack.** Python + Flask + SQLite + waitress is sufficient for the
zero-knowledge model: the server stores opaque blobs and does one atomic
`UPDATE … RETURNING`. No framework change is needed and none would buy a
security property. The only additions are:

- a **sweeper** (in-process thread + `tools/sweep.py` for a timer),
- an **in-memory rate limiter**,
- a **build/release toolchain** (`tools/build_release.py`,
  `tools/verify_release.py`) so the running code can be proven against the
  public repository.

No third-party crypto library is vendored: Web Crypto does AES-GCM, PBKDF2 and
HKDF. Nothing needs SRI except our own files, and those are hash-pinned at
startup and served with `integrity` attributes.

## 11. Migration plan for existing links

Existing links are the only copy of their destination and they are in the wild.

1. **Freeze writes, snapshot the database** (`data/secret-link.sqlite3` plus
   `-wal`) to `data/backups/` with a timestamp, on both the host and trinity.
2. **Classify**: `legacy` = every row in `links`. They keep resolving at
   `/<code>` and `/s/<code>` until they expire or are destroyed, as the prompt
   allows.
3. **Purge click data immediately** (owner instruction: no user data about link
   clicks): `DROP`/`DELETE` from `opens`, `visitors`, `share_tokens`, `alerts`;
   `VACUUM`; `login_attempts` cleared. Legacy link rows keep `code`, `target`,
   `max_uses`, `uses`, `expires_at` — the minimum needed to keep them working.
4. **Stop recording** on the legacy path: no IP, no UA, no Referer, no
   fingerprint, no per-open row. Only the counter moves, atomically.
5. **Do not re-encrypt legacy targets.** The server cannot encrypt a URL it has
   already seen, and pretending otherwise would be a false claim. The `/privacy`
   page states that links created before the cutover are legacy and were stored
   in plaintext; they expire on their own schedule and are then deleted.
6. **Sweep**: expired/destroyed legacy rows are deleted by the sweeper, target
   included.
7. **No data migration without the owner's explicit go-ahead** (prompt step 6).
   This plan is written, not executed, until that answer is recorded.

## 12. What the rebuild must prove

- The server never receives a destination URL, a note, or a key.
- Opening a link page does not consume a use; only a user click does.
- Concurrent consumes are exactly-once.
- The ciphertext is gone the moment the last use is spent.
- No IP, UA, Referer or fingerprint is stored for a click — not in SQLite, not in
  nginx logs.
- The deployed code is the published open-source code, and the site says how to
  check that.
