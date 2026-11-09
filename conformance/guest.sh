#!/usr/bin/env bash
# Runs inside the disposable Linux guest; started by run-vm.sh, never by hand on
# a workstation. Expects ~/in/harness (linux/arm64 binary), ~/in/portiko.json,
# ~/in/docker-compose.override.yml and the suite's source in ~/in/suite.
# Writes the suite's exported results and the logs to ~/results.
set -euo pipefail

PLANS=(
  "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]"
  "oidcc-config-certification-test-plan"
)
SUITE_IMAGE_TAG=${SUITE_IMAGE_TAG:?}
RESULTS=~/results
mkdir -p "$RESULTS/export"

echo "== packages"
export DEBIAN_FRONTEND=noninteractive
sudo -E apt-get update -qq
sudo -E apt-get install -y -qq docker.io docker-compose-v2 postgresql python3-venv curl >/dev/null

echo "== postgres"
sudo -u postgres psql -qc "CREATE ROLE portiko LOGIN PASSWORD 'portiko'"
sudo -u postgres createdb -O portiko portiko

echo "== suite ($SUITE_IMAGE_TAG)"
cd ~/in/suite
mkdir -p mongo/data
sudo IMAGE_TAG="$SUITE_IMAGE_TAG" docker compose -f docker-compose-prebuilt.yml -f ~/in/docker-compose.override.yml up -d --quiet-pull
for i in $(seq 1 120); do
  curl -ksf https://localhost.emobix.co.uk:8443/api/runner/available >/dev/null 2>&1 && break
  sleep 5
done
curl -ksf https://localhost.emobix.co.uk:8443/api/runner/available >/dev/null

echo "== harness"
~/in/harness >"$RESULTS/harness.log" 2>&1 &
HARNESS=$!
for i in $(seq 1 60); do
  curl -ksf --resolve host.docker.internal:9443:127.0.0.1 https://host.docker.internal:9443/health >/dev/null 2>&1 && break
  sleep 1
done
# From inside the suite's container, the way the suite will reach it.
sudo docker compose -f docker-compose-prebuilt.yml -f ~/in/docker-compose.override.yml exec -T server \
  sh -c 'getent hosts host.docker.internal' | tee "$RESULTS/server-resolves.txt"

echo "== plans"
python3 -m venv ~/venv
~/venv/bin/pip install -q -r scripts/requirements.txt
args=()
for p in "${PLANS[@]}"; do args+=("$p" ~/in/portiko.json); done
set +e
~/venv/bin/python scripts/run-test-plan.py --export-dir "$RESULTS/export" --verbose "${args[@]}" 2>&1 | tee "$RESULTS/run-test-plan.log"
status=${PIPESTATUS[0]}
set -e
echo "run-test-plan.py exit $status" | tee -a "$RESULTS/run-test-plan.log"

kill "$HARNESS" 2>/dev/null || true
wait "$HARNESS" 2>/dev/null || true
sudo docker compose -f docker-compose-prebuilt.yml -f ~/in/docker-compose.override.yml logs --no-color server >"$RESULTS/suite-server.log" 2>&1 || true
exit 0
