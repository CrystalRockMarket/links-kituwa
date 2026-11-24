#!/usr/bin/env bash
# End-to-end smoke test against a running instance.
#   tools/smoke.sh http://127.0.0.1:8848
set -euo pipefail
BASE="${1:-http://127.0.0.1:8848}"
JAR="$(mktemp)"; PAGE="$(mktemp)"
trap 'rm -f "$JAR" "$PAGE"' EXIT
say(){ printf '  %s\n' "$*"; }

fail(){ printf 'FAIL: %s\n' "$*" >&2; exit 1; }

code_of(){ grep -o 'code: [0-9]*' <<<"$1" | head -1 | awk '{print $2}'; }

say "health"
curl -fsS "$BASE/healthz" | grep -q '"ok":true' || fail "healthz"

say "signup"
curl -fsS -c "$JAR" -b "$JAR" "$BASE/signup" -o "$PAGE"
CSRF=$(grep -o 'name="csrf" value="[^"]*"' "$PAGE" | head -1 | sed 's/.*value="//;s/"//')
EMAIL="smoke$(date +%s)@example.com"
curl -fsS -c "$JAR" -b "$JAR" -o /dev/null -X POST "$BASE/signup" \
  --data-urlencode "csrf=$CSRF" --data-urlencode "email=$EMAIL" \
  --data-urlencode "password=a long enough password" || fail "signup"
say "  $EMAIL"

say "verify (token from the newest outbox mail)"
TOKEN=$(ls -t "${SL_DATA_DIR:-./data}"/outbox/*.eml | head -1 | xargs grep -oE '/verify/[A-Za-z0-9_-]+' | head -1 | cut -d/ -f3)
[ -n "$TOKEN" ] || fail "no verification token"
curl -fsS "$BASE/verify/$TOKEN" >/dev/null || fail "verify"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/verify/$TOKEN")" = "410" ] || fail "token reuse not refused"

say "login"
curl -fsS -c "$JAR" -b "$JAR" "$BASE/login" -o "$PAGE"
CSRF=$(grep -o 'name="csrf" value="[^"]*"' "$PAGE" | head -1 | sed 's/.*value="//;s/"//')
curl -fsS -c "$JAR" -b "$JAR" -o /dev/null -X POST "$BASE/login" \
  --data-urlencode "csrf=$CSRF" --data-urlencode "email=$EMAIL" \
  --data-urlencode "password=a long enough password" || fail "login"

say "create a one-time link"
curl -fsS -c "$JAR" -b "$JAR" "$BASE/app" -o "$PAGE"
CSRF=$(grep -o 'name="csrf" value="[^"]*"' "$PAGE" | head -1 | sed 's/.*value="//;s/"//')
curl -fsS -c "$JAR" -b "$JAR" -o /dev/null -X POST "$BASE/app/new" \
  --data-urlencode "csrf=$CSRF" --data-urlencode "target=https://example.com/smoke" \
  --data-urlencode "label=smoke" --data-urlencode "max_uses=1" || fail "create"

LINK=$(sqlite3 "${SL_DATA_DIR:-./data}/secret-link.sqlite3" "select max(code) from links")
[ -n "$LINK" ] || fail "no link row"

say "open once -> 302, open twice -> 410"
[ "$(curl -s -o /dev/null -w '%{http_code}' -A 'Mozilla/5.0 smoke' "$BASE/$LINK")" = "302" ] || fail "first open"
[ "$(curl -s -o /dev/null -w '%{http_code}' -A 'Mozilla/5.0 smoke' "$BASE/$LINK")" = "410" ] || fail "second open"

say "preview fetch does not consume (new link)"
curl -fsS -c "$JAR" -b "$JAR" "$BASE/app" -o "$PAGE"
CSRF=$(grep -o 'name="csrf" value="[^"]*"' "$PAGE" | head -1 | sed 's/.*value="//;s/"//')
curl -fsS -c "$JAR" -b "$JAR" -o /dev/null -X POST "$BASE/app/new" \
  --data-urlencode "csrf=$CSRF" --data-urlencode "target=https://example.com/preview" \
  --data-urlencode "max_uses=1"
LINK2=$(sqlite3 "${SL_DATA_DIR:-./data}/secret-link.sqlite3" "select max(code) from links")
curl -s -o /dev/null -w '' -A 'facebookexternalhit/1.1' "$BASE/$LINK2"
USES=$(sqlite3 "${SL_DATA_DIR:-./data}/secret-link.sqlite3" "select uses from links where code='$LINK2'")
[ "$USES" = "0" ] || fail "preview consumed a use"
[ "$(curl -s -o /dev/null -w '%{http_code}' -A 'Mozilla/5.0 smoke' "$BASE/$LINK2")" = "302" ] || fail "human open after preview"

say "all smoke checks passed"
