#!/usr/bin/env bash
# Runs the release gate (docs/conformance.md) in a disposable Linux Tart VM on
# cameron, and brings the results back:
#
#   conformance/run-vm.sh [results-dir]
#
# It tests the committed HEAD, not the working tree, and refuses a dirty tree so
# the commit it reports is the commit it tested. Nothing is shared into the
# guest: inputs are streamed in through `tart exec -i`, results streamed out.
# The clone is deleted on exit.
set -euo pipefail

IMAGE=${IMAGE:-ghcr.io/cirruslabs/ubuntu:24.04}
SUITE_REF=${SUITE_REF:-release-v5.3.4}       # git tag of the suite, and its image tag
SUITE_REPO=https://gitlab.com/openid/conformance-suite.git
GUEST_CPU=${GUEST_CPU:-4}
GUEST_MEM_MB=${GUEST_MEM_MB:-8192}
GUEST_DISK_GB=${GUEST_DISK_GB:-40}

REPO=$(cd "$(dirname "$0")/.." && pwd)
COMMIT=$(git -C "$REPO" rev-parse HEAD)
if [[ -n "$(git -C "$REPO" status --porcelain)" ]]; then
  echo "run-vm.sh: the working tree is dirty; commit first so the tested commit is exact" >&2
  exit 1
fi
RUN_ID=$(date -u +%Y%m%d-%H%M%S)-$$
VM=portiko-conformance-$RUN_ID
OUT=${1:-$REPO/conformance/results/$RUN_ID}
WORK=$(mktemp -d)
LEASE_ID=

cleanup() {
  set +e
  [[ -n "$LEASE_ID" ]] && tart-lease release --id "$LEASE_ID" 2>/dev/null
  if tart list --quiet 2>/dev/null | grep -qx "$VM"; then
    tart stop "$VM" >/dev/null 2>&1
    tart delete "$VM"
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "== preflight"
avail=$(df -g "$HOME" | awk 'NR==2 {print $4}')
(( avail >= 20 )) || { echo "only ${avail} GiB free; need 20" >&2; exit 1; }
if command -v tart-lease >/dev/null; then
  LEASE_ID=$(tart-lease acquire --label portiko-conformance --pid $$ --need-gb $(( GUEST_MEM_MB / 1024 + 4 )))
else
  echo "tart-lease not on PATH; proceeding without a lease" >&2
fi

echo "== inputs (Portiko $COMMIT, suite $SUITE_REF)"
mkdir -p "$WORK/src" "$WORK/in/suite"
git -C "$REPO" archive "$COMMIT" | tar -x -C "$WORK/src"
(cd "$WORK/src" && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -tags conformance -o "$WORK/in/harness" ./conformance/cmd/harness)
cp "$WORK/src/conformance/portiko.json" "$WORK/src/conformance/docker-compose.override.yml" "$WORK/src/conformance/guest.sh" "$WORK/in/"
git -c advice.detachedHead=false clone -q --depth 1 --branch "$SUITE_REF" "$SUITE_REPO" "$WORK/suite"
SUITE_COMMIT=$(git -C "$WORK/suite" rev-parse HEAD)
git -C "$WORK/suite" archive HEAD | tar -x -C "$WORK/in/suite"

echo "== guest $VM"
tart clone "$IMAGE" "$VM"
tart set "$VM" --cpu "$GUEST_CPU" --memory "$GUEST_MEM_MB" --disk-size "$GUEST_DISK_GB"
tart run "$VM" --no-graphics --no-audio >"$WORK/tart-run.log" 2>&1 &
for _ in $(seq 1 60); do tart exec "$VM" true 2>/dev/null && break; sleep 5; done
tart exec "$VM" true
# The image's root filesystem does not grow on its own to the new disk size.
tart exec "$VM" bash -c 'sudo growpart /dev/vda 1 >/dev/null 2>&1; sudo resize2fs /dev/vda1 >/dev/null 2>&1; df -h /' || true

tar -C "$WORK" -cf - in | tart exec -i "$VM" tar -x -C /home/admin
tart exec "$VM" env SUITE_IMAGE_TAG="$SUITE_REF" bash /home/admin/in/guest.sh 2>&1 | tee "$WORK/guest.log"

echo "== results -> $OUT"
mkdir -p "$OUT"
tart exec "$VM" tar -C /home/admin/results -cf - . | tar -x -C "$OUT"
cp "$WORK/guest.log" "$OUT/"
cat >"$OUT/run.txt" <<EOF
run         $RUN_ID
portiko     $COMMIT
suite       $SUITE_REF ($SUITE_COMMIT)
image       $IMAGE
guest       ${GUEST_CPU} CPU, ${GUEST_MEM_MB} MB
EOF
cat "$OUT/run.txt"
