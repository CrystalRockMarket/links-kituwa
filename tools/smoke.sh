#!/usr/bin/env bash
# End-to-end smoke test against a running instance.
#   tools/smoke.sh http://127.0.0.1:8891
set -euo pipefail
BASE="${1:-http://127.0.0.1:8891}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
say(){ printf '  %s\n' "$*"; }
fail(){ printf 'FAIL: %s\n' "$*" >&2; exit 1; }
code(){ curl -s -o /dev/null -w '%{http_code}' "$@"; }

say "health"
curl -fsS "$BASE/healthz" | grep -q '"ok":true' || fail "healthz"

say "create an encrypted link (server sees only a blob)"
read -r CT IV <<<"$(python3 -c 'import os,base64;b=lambda n:base64.urlsafe_b64encode(os.urandom(n)).decode().rstrip("=");print(b(48), b(12))')"
BODY=$(printf '{"ciphertext":"%s","iv":"%s","options":{"max_uses":1,"expires_in":3600}}' "$CT" "$IV")
CREATED=$(curl -fsS -X POST "$BASE/api/links" -H 'Content-Type: application/json' -d "$BODY")
ID=$(python3 -c 'import json,sys;print(json.loads(sys.argv[1])["id"])' "$CREATED")
TOKEN=$(python3 -c 'import json,sys;print(json.loads(sys.argv[1])["manage_token"])' "$CREATED")
say "  /l/$ID"

say "the page does not spend a use"
[ "$(code "$BASE/l/$ID")" = "200" ] || fail "decrypt page"
[ "$(code "$BASE/api/links/$ID")" = "200" ] || fail "peek"
USES=$(curl -fsS "$BASE/api/links/$ID" | python3 -c 'import json,sys;print(json.load(sys.stdin)["uses"])')
[ "$USES" = "0" ] || fail "a page fetch spent a use"

say "headers and no cookie on the secret surface"
H=$(curl -sI "$BASE/l/$ID")
grep -qi 'content-security-policy:.*default-src' <<<"$H" || fail "no CSP"
grep -qi 'referrer-policy: no-referrer' <<<"$H" || fail "no referrer policy"
grep -qi 'set-cookie' <<<"$H" && fail "cookie on /l/"
grep -qi 'hub.kituwa.com' <<<"$H" && fail "third-party origin on /l/"

say "consume once -> 200, again -> 410"
[ "$(code -X POST "$BASE/api/links/$ID/consume" -H 'Content-Type: application/json' -d '{}')" = "200" ] || fail "first consume"
[ "$(code -X POST "$BASE/api/links/$ID/consume" -H 'Content-Type: application/json' -d '{}')" = "410" ] || fail "second consume"

say "manage token reports the spent state"
curl -fsS -X POST "$BASE/api/manage/$ID" -H 'Content-Type: application/json' \
  -d "{\"token\":\"$TOKEN\",\"action\":\"state\"}" | grep -q '"state": *"spent"' \
  || fail "manage state"

say "release provenance is served"
if curl -fsS "$BASE/release.json" -o "$TMP/release.json" 2>/dev/null; then
  grep -q '"sha256"' "$TMP/release.json" || fail "release.json has no sha256"
  say "  manifest present"
else
  say "  no manifest (development run)"
fi
[ "$(code "$BASE/verify")" = "200" ] || fail "/verify"

say "all smoke checks passed"
