#!/usr/bin/env bash
# Disposable Docker lifecycle test; never targets a real deployment project.
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
project="inspector-lifecycle-$$"
cleanup() {
  result=$?
  if (( result != 0 )); then cat "$tmp/up.log" "$tmp/nft.log" 2>/dev/null || true; fi
  docker rm -f "$project-tunnel" "$project-legacy" >/dev/null 2>&1 || true
  docker compose --env-file "$tmp/fixture.env" -f "$tmp/compose.multi.yaml" -p "$project" down >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT
REAL_DOCKER=$(command -v docker)
export REAL_DOCKER
image=$(docker image inspect infrastructure-inspector-test:ci --format '{{.Id}}')
mkdir -p "$tmp/hosts/default" "$tmp/hosts/ai-server" "$tmp/hosts/third"
for host in default ai-server third; do
  printf 'disposable identity\n' > "$tmp/hosts/$host/identity"
  printf 'disposable known host\n' > "$tmp/hosts/$host/known_hosts"
done
registry="$tmp/host-registry.json"
write_registry() {
  local ai_ip=$1 third_ip=${2:-}
  if [[ -n $third_ip ]]; then
    printf '{"default_host":"default","hosts":[{"id":"default","label":"Server","target":"audit@10.253.252.1"},{"id":"ai-server","label":"AI Server","target":"audit@%s"},{"id":"third","label":"Third","target":"audit@%s"}]}\n' "$ai_ip" "$third_ip" > "$registry"
  else
    printf '{"default_host":"default","hosts":[{"id":"default","label":"Server","target":"audit@10.253.252.1"},{"id":"ai-server","label":"AI Server","target":"audit@%s"}]}\n' "$ai_ip" > "$registry"
  fi
}
write_registry 192.0.2.10
cat > "$tmp/fixture.env" <<ENV
INSPECTOR_IMAGE_ID=$image
INSPECTOR_EGRESS_BRIDGE=br-lc-$$
INSPECTOR_HOST_REGISTRY_PATH=$registry
INSPECTOR_HOST_SECRETS_DIR=$tmp/hosts
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
    volumes:
      - type: bind
        source: ${INSPECTOR_HOST_REGISTRY_PATH:?}
        target: /run/secrets/host-registry.json
        read_only: true
      - type: bind
        source: ${INSPECTOR_HOST_SECRETS_DIR:?}
        target: /run/secrets/inspector-hosts
        read_only: true
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

# Exercise the real unit actions with a fake nft executable. A rejected
# registry/allowlist combination must reach neither nft nor Docker creation.
export NFT_CALL_LOG="$tmp/nft.log" NFT_EXPECTED_JSON="$tmp/expected-policy.json"
cat > "$tmp/bin/nft" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$NFT_CALL_LOG"
case "$1" in
  -c|-f) exit 0 ;;
  -j) cat "$NFT_EXPECTED_JSON" ;;
  *) exit 1 ;;
esac
SH
chmod +x "$tmp/bin/nft"
# The real installer requires br_netfilter even when nft is disposable. Some
# unprivileged CI runners cannot load it; negative authorization paths still
# run there, while hosts with the prerequisite also exercise installation.
policy_prerequisite=false
if [[ -r /proc/sys/net/bridge/bridge-nf-call-iptables ]] &&
   [[ $(cat /proc/sys/net/bridge/bridge-nf-call-iptables) == 1 ]]; then
  policy_prerequisite=true
fi
# Supply the actual bridge through the environment to avoid a second policy
# definition in this disposable test.
write_expected_policy() {
  python3 - "$NFT_EXPECTED_JSON" "$INSPECTOR_UNIT_EGRESS_BRIDGE" "$@" <<'PY'
import json
import runpy
import sys
policy = runpy.run_path("scripts/network_policy_verify.py")["expected_policy"]
rules = policy("10.253.252.10", "02:42:ac:1c:fc:0a", "10.253.252.1",
               "10.253.253.10", sys.argv[2], sys.argv[3:])
with open(sys.argv[1], "w", encoding="utf-8") as output:
    json.dump({"nftables": rules}, output)
PY
}
assert_rejected() {
  local case_name=$1 mode=$2 allowlist=$3 before after
  : > "$NFT_CALL_LOG"
  before=$(docker ps -aq --no-trunc --filter "label=com.docker.compose.project=$project" --filter 'label=com.docker.compose.service=inspector')
  if INSPECTOR_UNIT_EXTERNAL_IPS="$allowlist" PATH="$tmp/bin:$PATH" timeout 5s \
      bash scripts/multi_host_service.sh "$mode" >"$tmp/$case_name-$mode.log" 2>&1; then
    echo "Expected $case_name to reject $mode" >&2; exit 1
  fi
  [[ ! -s $NFT_CALL_LOG ]] || { echo "Policy action reached nft for $case_name" >&2; exit 1; }
  after=$(docker ps -aq --no-trunc --filter "label=com.docker.compose.project=$project" --filter 'label=com.docker.compose.service=inspector')
  [[ $before == "$after" ]]
  [[ $(docker inspect --format '{{.State.Running}}' "$project-legacy") == true ]]
  [[ $(docker inspect --format '{{.Id}}' "$project-tunnel") == "$tunnel" ]]
}
reject_all_actions() {
  local case_name=$1 allowlist=$2 mode
  for mode in policy-start check start; do
    assert_rejected "$case_name" "$mode" "$allowlist"
  done
}
write_expected_policy 192.0.2.10
if [[ $policy_prerequisite == true ]]; then
  : > "$NFT_CALL_LOG"
  PATH="$tmp/bin:$PATH" bash scripts/multi_host_service.sh policy-start
  rg -q '^-f ' "$NFT_CALL_LOG"
  PATH="$tmp/bin:$PATH" bash scripts/multi_host_service.sh check
fi
# The effective bind mount, not an unrelated unit path, is authoritative.
cp "$registry" "$tmp/alternate-registry.json"
python3 - "$tmp/alternate-registry.json" <<'PY'
import json
import sys
path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    data = json.load(source)
data["hosts"][1]["target"] = "audit@192.0.2.11"
with open(path, "w", encoding="utf-8") as output:
    json.dump(data, output)
PY
cp "$tmp/fixture.env" "$tmp/original.env"
sed "s|^INSPECTOR_HOST_REGISTRY_PATH=.*|INSPECTOR_HOST_REGISTRY_PATH=$tmp/alternate-registry.json|" \
  "$tmp/original.env" > "$tmp/fixture.env"
reject_all_actions mounted_registry_differs '192.0.2.10'
write_expected_policy 192.0.2.11
if [[ $policy_prerequisite == true ]]; then
  INSPECTOR_UNIT_EXTERNAL_IPS=192.0.2.11 PATH="$tmp/bin:$PATH" \
    bash scripts/multi_host_service.sh policy-start
fi
cp "$tmp/original.env" "$tmp/fixture.env"
write_expected_policy 192.0.2.10
reject_all_actions extra '192.0.2.10 192.0.2.11'
reject_all_actions duplicate '192.0.2.10 192.0.2.10'
reject_all_actions malformed '192.0.2.999'
reject_all_actions hostname 'example.com'
reject_all_actions ipv6 '2001:db8::1'
reject_all_actions multiline $'192.0.2.10\n192.0.2.11'
reject_all_actions default_gateway '192.0.2.10 10.253.252.1'
reject_all_actions substituted '192.0.2.11'
write_registry example.com
reject_all_actions registry_hostname '192.0.2.10'
write_registry 2001:db8::1
reject_all_actions registry_ipv6 '192.0.2.10'
write_registry 192.0.2.999
reject_all_actions registry_malformed_ip '192.0.2.10'
write_registry 192.0.2.10 192.0.2.11
reject_all_actions missing '192.0.2.10'
write_registry 192.0.2.10 192.0.2.10
reject_all_actions duplicate_registry_destinations '192.0.2.10'
write_registry 192.0.2.10 192.0.2.11
write_expected_policy 192.0.2.11 192.0.2.10
if [[ $policy_prerequisite == true ]]; then
  INSPECTOR_UNIT_EXTERNAL_IPS='192.0.2.11 192.0.2.10' PATH="$tmp/bin:$PATH" \
    bash scripts/multi_host_service.sh policy-start
  INSPECTOR_UNIT_EXTERNAL_IPS='192.0.2.11 192.0.2.10' PATH="$tmp/bin:$PATH" \
    bash scripts/multi_host_service.sh check
fi
write_registry 192.0.2.10
write_expected_policy 192.0.2.10
mv "$registry" "$tmp/registry.saved"
reject_all_actions missing_registry '192.0.2.10'
mv "$tmp/registry.saved" "$registry"
cp "$registry" "$tmp/registry.saved"
printf '{not-json SENSITIVE_REGISTRY_BYTES\n' > "$registry"
reject_all_actions invalid_json '192.0.2.10'
if rg -q 'SENSITIVE_REGISTRY_BYTES' "$tmp"/invalid_json-*.log; then
  echo 'Registry contents leaked in a validation failure' >&2; exit 1
fi
cp "$tmp/registry.saved" "$registry"
python3 - "$registry" <<'PY'
import json
import sys
path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    data = json.load(source)
data["default_host"] = "ai-server"
with open(path, "w", encoding="utf-8") as output:
    json.dump(data, output)
PY
reject_all_actions wrong_default '192.0.2.10'
cp "$tmp/registry.saved" "$registry"
chmod 0666 "$registry"
reject_all_actions unsafe_registry '192.0.2.10'
chmod 0000 "$registry"
reject_all_actions unreadable_registry '192.0.2.10'
chmod 0644 "$registry"
docker rm -f "$project-legacy" >/dev/null

# A killed foreground Compose client leaves its container running. Simulate
# systemd's post-stop action with the same ExecStopPost helper.
if [[ $policy_prerequisite == true ]]; then
  PATH="$tmp/bin:$PATH" bash scripts/multi_host_service.sh start >"$tmp/up.log" 2>&1 &
else
  docker compose --env-file "$tmp/fixture.env" -f "$tmp/compose.multi.yaml" -p "$project" \
    up --no-deps --no-build --pull never --exit-code-from inspector inspector >"$tmp/up.log" 2>&1 &
fi
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
docker run -d --name "$project-legacy" --label "com.docker.compose.project=$project" --label 'com.docker.compose.service=inspector' "$image" python -c 'import time; time.sleep(600)' >/dev/null
write_registry 192.0.2.11
bash scripts/multi_host_service.sh cleanup
[[ $(docker inspect --format '{{.State.Running}}' "$project-legacy") == true ]]
[[ $(docker inspect --format '{{.Id}}' "$project-tunnel") == "$tunnel" ]]
write_registry 192.0.2.10
docker rm -f "$project-legacy" >/dev/null
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
mv "$registry" "$tmp/registry.saved"
bash scripts/multi_host_service.sh cleanup
mv "$tmp/registry.saved" "$registry"
[[ $(docker inspect --format '{{.State.Running}}' "$candidate") == false ]]
echo 'Disposable lifecycle, legacy isolation, Tunnel continuity, and failed cleanup checks passed'
