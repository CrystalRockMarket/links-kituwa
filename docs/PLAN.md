# Secret Link — plan, decisions, rollout

Pack 2.27.0. Protocols applied: **01, 02, 05, 13, 15, 16, 18, 21, 22, 24, 27,
32, 35, 36**, plus Protocol 1 rules 3, 7 and 9.

## 1. What is already proven (local)

- Link lifecycle: exact budgets, atomic decrement, destruction, expiry, manual
  destroy/pause/resume — `tests/test_links.py`.
- Preview fetches do not consume a use; the human click does — `tests/test_links.py`,
  `tests/test_web.py`.
- Concurrency: 10 simultaneous opens of a 3-use link → exactly 3 succeed.
- Accounts, CSRF, isolation, headers, share attribution — `tests/test_web.py`.
- End-to-end through `run.py` and waitress — `tools/smoke.sh` (all checks pass).

## 2. Open decisions — these change the build, so they are asked before wiring

1. **Short-link hostname.** Where the short URL lives decides every recorded
   URL, the DNS record and the cookie scope.
   - A. `kituwa.link/<code>` — shortest, cleanest to read out loud; needs one
     new registered domain plus DNS and a certificate.
   - B. `s.kituwa.com/<code>` — no new domain, one DNS record, 8 characters
     typed instead of 12.
   - C. `secret-link.kituwa.com/s/<code>` — no new DNS name at all; longest.
   - Recommendation: **B** unless the bare `kituwa.link` name matters enough to
     buy and own it.
2. **Who may create pass-along links.** Attribution only works if a recipient
   can mint one.
   - A. Any recipient of a *tracking* link may pass it on with attribution;
     budgeted links do not offer it (a one-use link cannot be forwarded anyway).
     Recommended.
   - B. Only the owner mints pass-along links; recipients are tracked only by
     device and referrer.
3. **Where the redirect executes** (Protocol 1 rule 7). A shortener must answer
   on every request, so it cannot be a static artifact.
   - A. A tiny resolver on `kituwa-cloud-1` reads a replicated, read-only copy
     of the link table and answers the redirect; all writes, dashboards and
     mail run on trinity and sync down. Links keep working when trinity is
     down. Recommended.
   - B. The whole app runs on trinity behind a host redirect: simplest, but the
     shortener dies whenever the worker is down — which is exactly the case a
     short link must survive.

## 3. Privacy consequence of IP logging (protocol 13)

The owner asked for IPs, so the default is `SL_IP_MODE=full`. That makes the
service a personal-data processor for every recipient. Before public launch:

- The link owner sees only their own links' data (already enforced).
- Add a retention window (suggest 90 days for `opens.ip`) and a delete-my-data
  path for an account.
- State on the landing page what is recorded, because recipients never agreed to
  anything.

## 4. Delivery sequence once decisions are answered

1. Fix `SL_BASE_URL` and the short host; re-run `tools/smoke.sh` against it.
2. Pocket ID: `operators` client for `/admin` (redirect-verified), `members`
   client if consumer login moves to SSO (email/password stays available per
   protocol 01). Secret to a 0600 file, never echoed.
3. Deploy: app on trinity (systemd, waitress), resolver + nginx site on
   `kituwa-cloud-1`, TLS, headers already set in-app.
4. DNS record; verify with a real one-time link opened once from a phone.
5. Register: Hub card, Portfolio + Timeline (with `live_date` evidence), Start
   shortcut, Atlas node (public), watchdog page, `site_logins.py` row.
6. Work log to Trilium, backup to Gitea + GitHub mirror, owner tasks to Vikunja.

## 5. Known gaps in this increment

- No admin console yet (`/admin` is Pocket ID's job, not built here).
- No retention job, no account deletion, no export.
- Alerts are stored and listed in the dashboard; no email delivery wired until
  SMTP is configured.
- QR code rendering and custom slugs are not implemented.
