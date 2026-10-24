#!/usr/bin/env bash
# Disposable Docker lifecycle test; never targets a real deployment project.
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
project="inspector-lifecycle-$$"
cleanup() {
  result=$?
  if (( result != 0 )); then cat "$tmp/up.log" 2>/dev/null || true; fi
  docker rm -f "$project-tunnel" "$project-legacy" >/dev/null 2>&1 || true
  docker compose --env-file "$tmp/fixture.env" -f "$tmp/compose.multi.yaml" -p "$project" down >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT
REAL_DOCKER=$(command -v docker)
export REAL_DOCKER
image=$(docker image inspect infrastructure-inspector-test:ci --format '{{.Id}}')
cat > "$tmp/fixture.env" <<ENV
INSPECTOR_IMAGE_ID=$image
INSPECTOR_EGRESS_BRIDGE=br-lc-$$
ENV
cat > "$tmp/compose.multi.yaml" <<'YAML'
name: infrastructure-inspector
services:
  inspector:
    image: ${INSPECTOR_IMAGE_ID:?}
    pull_policy: never
    command: [python, -c, 'import time; time.sleep(600)']
    restart: "no"
    environment:
      INSPECTOR_HOST_MODE: multi
    networks:
      mcp-private:
        ipv4_address: 10.253.252.10
        mac_address: 02:42:ac:1c:fc:0a
      ssh-egress:
        ipv4_address: 10.253.253.10
  tunnel-client:
    image: ${INSPECTOR_IMAGE_ID:?}
    command: [python, -c, 'import time; time.sleep(600)']
    restart: unless-stopped
    networks: [mcp-private]
networks:
  mcp-private:
    internal: true
    ipam:
      config:
        - subnet: 10.253.252.0/24
          gateway: 10.253.252.1
  ssh-egress:
    driver_opts:
      com.docker.network.bridge.name: ${INSPECTOR_EGRESS_BRIDGE:?}
    ipam:
      config:
        - subnet: 10.253.253.0/24
YAML
export INSPECTOR_UNIT_COMPOSE="$tmp/compose.multi.yaml"
export INSPECTOR_UNIT_ENV="$tmp/fixture.env"
export INSPECTOR_UNIT_PROJECT="$project"
export INSPECTOR_UNIT_PRIVATE_IP=10.253.252.10
export INSPECTOR_UNIT_PRIVATE_MAC=02:42:ac:1c:fc:0a
export INSPECTOR_UNIT_PRIVATE_GATEWAY=10.253.252.1
export INSPECTOR_UNIT_EGRESS_IP=10.253.253.10
export INSPECTOR_UNIT_EGRESS_BRIDGE=br-lc-$$
export INSPECTOR_UNIT_EXTERNAL_IPS=192.0.2.10

# Validate the shipped units against a disposable unit search path.
mkdir "$tmp/units"
cp deploy/systemd/*.service "$tmp/units/"
printf '[Unit]\nDescription=Disposable Docker dependency\n[Service]\nExecStart=/bin/true\n' > "$tmp/units/docker.service"
SYSTEMD_UNIT_PATH="$tmp/units:/usr/lib/systemd/system" systemd-analyze verify "$tmp/units/infrastructure-inspector-policy.service" "$tmp/units/infrastructure-inspector-multi.service"

# ExecStopPost must not touch a legacy Inspector after ExecStartPre fails.
docker run -d --name "$project-legacy" --label "com.docker.compose.project=$project" --label 'com.docker.compose.service=inspector' "$image" python -c 'import time; time.sleep(600)' >/dev/null
docker run -d --name "$project-tunnel" --label "com.docker.compose.project=$project" --label 'com.docker.compose.service=tunnel-client' "$image" python -c 'import time; time.sleep(600)' >/dev/null
tunnel=$(docker inspect --format '{{.Id}}' "$project-tunnel")
mkdir "$tmp/bin"
cat > "$tmp/bin/nft" <<'SH'
#!/bin/sh
exit 1
SH
chmod +x "$tmp/bin/nft"
if PATH="$tmp/bin:$PATH" bash scripts/multi_host_service.sh check >"$tmp/preflight.log" 2>&1; then
  echo 'Expected policy verification failure' >&2; exit 1
fi
bash scripts/multi_host_service.sh cleanup
[[ $(docker inspect --format '{{.State.Running}}' "$project-legacy") == true ]]
[[ $(docker inspect --format '{{.Id}}' "$project-tunnel") == "$tunnel" ]]
docker rm -f "$project-legacy" >/dev/null

# A killed foreground Compose client leaves its container running. Simulate
# systemd's post-stop action with the same ExecStopPost helper.
docker compose --env-file "$tmp/fixture.env" -f "$tmp/compose.multi.yaml" -p "$project" up --no-deps --no-build --pull never --exit-code-from inspector inspector >"$tmp/up.log" 2>&1 &
compose_pid=$!
for _ in $(seq 1 40); do
  candidate=$(docker compose --env-file "$tmp/fixture.env" -f "$tmp/compose.multi.yaml" -p "$project" ps -q inspector)
  [[ -n $candidate ]] && [[ $(docker inspect --format '{{.State.Running}}' "$candidate") == true ]] && break
  sleep 0.25
done
[[ -n ${candidate:-} ]]
kill -KILL "$compose_pid"
wait "$compose_pid" 2>/dev/null || true
[[ $(docker inspect --format '{{.State.Running}}' "$candidate") == true ]]
bash scripts/multi_host_service.sh cleanup
# Emulate Docker versions that clear all operational network data on stop.
export TEST_CANDIDATE="$candidate"
cat > "$tmp/bin/docker" <<'SH'
#!/usr/bin/env bash
if [[ $1 == inspect && $2 == "$TEST_CANDIDATE" ]]; then
  "$REAL_DOCKER" inspect "$2" | jq '.[0].NetworkSettings.Networks = {}'
  exit
fi
exec "$REAL_DOCKER" "$@"
SH
chmod +x "$tmp/bin/docker"
PATH="$tmp/bin:$PATH" bash scripts/multi_host_service.sh cleanup
rm "$tmp/bin/docker"
[[ $(docker inspect --format '{{.State.Running}}' "$candidate") == false ]]
[[ $(docker inspect --format '{{.Id}}' "$project-tunnel") == "$tunnel" ]]
[[ $(docker inspect --format '{{.State.Running}}' "$project-tunnel") == true ]]

# A failed Docker stop must fail verification and leave the firewall marker.
docker compose --env-file "$tmp/fixture.env" -f "$tmp/compose.multi.yaml" -p "$project" up -d --no-deps --no-build --pull never inspector >/dev/null
printf 'installed\n' > "$tmp/policy-marker"
if INSPECTOR_UNIT_EGRESS_BRIDGE=br-wrong-$$ bash scripts/multi_host_service.sh cleanup >"$tmp/bridge-failure.log" 2>&1; then
  echo 'Expected Compose/policy bridge mismatch failure' >&2; exit 1
fi
[[ $(cat "$tmp/policy-marker") == installed ]]
[[ $(docker inspect --format '{{.State.Running}}' "$candidate") == true ]]
docker update --restart unless-stopped "$candidate" >/dev/null
if bash scripts/multi_host_service.sh cleanup >"$tmp/identity-failure.log" 2>&1; then
  echo 'Expected identity mismatch failure' >&2; exit 1
fi
[[ $(cat "$tmp/policy-marker") == installed ]]
[[ $(docker inspect --format '{{.State.Running}}' "$candidate") == true ]]
docker update --restart no "$candidate" >/dev/null
cat > "$tmp/bin/docker" <<'SH'
#!/usr/bin/env bash
if [[ $1 == stop ]]; then exit 1; fi
exec "$REAL_DOCKER" "$@"
SH
chmod +x "$tmp/bin/docker"
if PATH="$tmp/bin:$PATH" bash scripts/multi_host_service.sh cleanup >"$tmp/stop-failure.log" 2>&1; then
  echo 'Expected Docker stop failure' >&2; exit 1
fi
[[ $(cat "$tmp/policy-marker") == installed ]]
[[ $(docker inspect --format '{{.State.Running}}' "$candidate") == true ]]
cat > "$tmp/bin/docker" <<'SH'
#!/usr/bin/env bash
if [[ $1 == stop ]]; then sleep 30; exit 0; fi
exec "$REAL_DOCKER" "$@"
SH
chmod +x "$tmp/bin/docker"
started=$SECONDS
if PATH="$tmp/bin:$PATH" bash scripts/multi_host_service.sh cleanup >"$tmp/stop-timeout.log" 2>&1; then
  echo 'Expected bounded Docker timeout failure' >&2; exit 1
fi
(( SECONDS - started < 18 ))
[[ $(cat "$tmp/policy-marker") == installed ]]
[[ $(docker inspect --format '{{.State.Running}}' "$candidate") == true ]]
cat > "$tmp/bin/docker" <<'SH'
#!/bin/sh
exit 1
SH
chmod +x "$tmp/bin/docker"
if PATH="$tmp/bin:$PATH" bash scripts/multi_host_service.sh cleanup >"$tmp/unavailable.log" 2>&1; then
  echo 'Expected Docker unavailability failure' >&2; exit 1
fi
[[ $(cat "$tmp/policy-marker") == installed ]]
[[ $(docker inspect --format '{{.State.Running}}' "$candidate") == true ]]
bash scripts/multi_host_service.sh cleanup
[[ $(docker inspect --format '{{.State.Running}}' "$candidate") == false ]]
echo 'Disposable lifecycle, legacy isolation, Tunnel continuity, and failed cleanup checks passed'
