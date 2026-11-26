#!/usr/bin/env bash
# Build, publish and prove a release.
#
#   1. build a deterministic artifact from the current commit and sign it
#   2. copy it to kituwa-cloud-1, extract into releases/<version>-<commit>
#   3. switch the `current` symlink and restart the service
#   4. recompute the tree hash on the host and write state.json for /verify
#
# The host never builds anything: it receives a finished artifact (Protocol 1
# rule 7).
set -euo pipefail

HOST="${SL_HOST_ALIAS:-kituwa-cloud-1}"
ROOT=/home/ubuntu/services/links-kituwa
cd "$(dirname "$0")/.."

./tools/build_release.py

read -r TARBALL SHA COMMIT VERSION <<<"$(python3 - <<'PY'
import json
m = json.load(open("dist/release.json"))
print(m["tarball"], m["sha256"], m["commit_short"], m["version"])
PY
)"
REL="${VERSION}-${COMMIT}"
echo "publishing ${TARBALL} (${SHA:0:16}…) as ${REL}"

scp -q "dist/${TARBALL}" dist/release.json dist/release.json.sig dist/release.pub "${HOST}:/tmp/"

ssh "$HOST" "sudo -n bash -s" <<EOF
set -euo pipefail
ROOT=${ROOT}
REL=${REL}
TARBALL=${TARBALL}

mkdir -p "\$ROOT/releases/\$REL" "\$ROOT/data/release"
tar -xzf "/tmp/\$TARBALL" -C "\$ROOT/releases/\$REL" --strip-components=1
chown -R ubuntu:ubuntu "\$ROOT/releases/\$REL"

ln -sfn "\$ROOT/releases/\$REL" "\$ROOT/current"
chown -h ubuntu:ubuntu "\$ROOT/current"

install -o ubuntu -g ubuntu -m 0644 /tmp/release.json "\$ROOT/data/release/release.json"
install -o ubuntu -g ubuntu -m 0644 /tmp/release.json.sig "\$ROOT/data/release/release.json.sig"
install -o ubuntu -g ubuntu -m 0644 /tmp/release.pub "\$ROOT/data/release/release.pub"
install -o ubuntu -g ubuntu -m 0644 "/tmp/\$TARBALL" "\$ROOT/data/release/\$TARBALL"
rm -f "/tmp/\$TARBALL" /tmp/release.json /tmp/release.json.sig /tmp/release.pub

systemctl daemon-reload
systemctl restart links-kituwa
sleep 2
systemctl is-active links-kituwa

cd "\$ROOT/current"
"\$ROOT/.venv/bin/python" tools/verify_release.py \
  --manifest "\$ROOT/data/release/release.json" --dir "\$ROOT/current" --write-state
chown ubuntu:ubuntu "\$ROOT/data/release/state.json"
EOF

echo "--- live checks ---"
curl -fsS https://links.kituwa.com/healthz; echo
curl -fsS https://links.kituwa.com/release.json | python3 -c 'import json,sys;m=json.load(sys.stdin);print("live commit",m["commit_short"],"tree",m["tree"][:16])'
curl -fsS https://links.kituwa.com/verify | grep -o 'RESULT\|MISMATCH' | head -1 || true
