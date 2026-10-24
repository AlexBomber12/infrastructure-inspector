#!/usr/bin/env bash
# Operator-side systemd adapter. Never mount the Docker socket into Inspector.
set -euo pipefail

fail() { echo "Multi-host Inspector lifecycle: $*" >&2; exit 1; }
: "${INSPECTOR_UNIT_COMPOSE:?}"
: "${INSPECTOR_UNIT_ENV:?}"
: "${INSPECTOR_UNIT_PROJECT:?}"
: "${INSPECTOR_UNIT_PRIVATE_IP:?}"
: "${INSPECTOR_UNIT_PRIVATE_MAC:?}"
: "${INSPECTOR_UNIT_PRIVATE_GATEWAY:?}"
: "${INSPECTOR_UNIT_EGRESS_IP:?}"
: "${INSPECTOR_UNIT_EGRESS_BRIDGE:?}"
[[ $INSPECTOR_UNIT_PROJECT =~ ^[a-z0-9][a-z0-9_-]*$ ]] || fail 'invalid project name'
[[ $INSPECTOR_UNIT_ENV == /* && -f $INSPECTOR_UNIT_COMPOSE && -f $INSPECTOR_UNIT_ENV ]] || fail 'deployment files missing'
[[ $(realpath -- "$INSPECTOR_UNIT_COMPOSE") == "$INSPECTOR_UNIT_COMPOSE" ]] || fail 'Compose path must be absolute and canonical'
[[ $(basename -- "$INSPECTOR_UNIT_COMPOSE") == compose.multi.yaml ]] || fail 'expected multi-host Compose file'
read -r -a external_ips <<< "${INSPECTOR_UNIT_EXTERNAL_IPS-}"
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
policy=("$INSPECTOR_UNIT_PRIVATE_IP" "$INSPECTOR_UNIT_PRIVATE_MAC" "$INSPECTOR_UNIT_PRIVATE_GATEWAY" "$INSPECTOR_UNIT_EGRESS_IP" "$INSPECTOR_UNIT_EGRESS_BRIDGE" "${external_ips[@]}")
compose=(docker compose --env-file "$INSPECTOR_UNIT_ENV" -f "$INSPECTOR_UNIT_COMPOSE" -p "$INSPECTOR_UNIT_PROJECT")
# Bound every Docker API request, including state verification. Docker stop has
# its own shorter grace period, so the outer timeout also bounds a stuck daemon.
docker_bounded() { timeout 12s docker "$@"; }

validate_contract() {
  command -v jq >/dev/null || fail 'jq is required; policy retained'
  # Resolve the reviewed configuration before touching any container. A
  # failed resolution is an unresolved state, never permission to stop.
  config=$(timeout 12s "${compose[@]}" config --format json) || fail 'cannot resolve reviewed Compose configuration; policy retained'
  expected_hash=$(timeout 12s "${compose[@]}" config --hash inspector) || fail 'cannot resolve Inspector hash; policy retained'
  expected_hash=${expected_hash#inspector }
  [[ $expected_hash =~ ^[a-f0-9]{64}$ ]] || fail 'invalid Inspector hash; policy retained'
  expected_image=$(jq -er '.services.inspector.image' <<< "$config") || fail 'missing Inspector image; policy retained'
  [[ $expected_image =~ ^sha256:[a-f0-9]{64}$ ]] || fail 'Inspector image is not an immutable ID; policy retained'
  jq -e --arg p "$INSPECTOR_UNIT_PROJECT" --arg ip "$INSPECTOR_UNIT_PRIVATE_IP" --arg mac "$INSPECTOR_UNIT_PRIVATE_MAC" --arg eip "$INSPECTOR_UNIT_EGRESS_IP" --arg gateway "$INSPECTOR_UNIT_PRIVATE_GATEWAY" --arg bridge "$INSPECTOR_UNIT_EGRESS_BRIDGE" '
    .name == $p and (.services | keys == ["inspector", "tunnel-client"]) and
    .services.inspector.environment.INSPECTOR_HOST_MODE == "multi" and
    .services.inspector.restart == "no" and
    .services["tunnel-client"].restart == "unless-stopped" and
    .services.inspector.networks["mcp-private"].ipv4_address == $ip and
    (.services.inspector.networks["mcp-private"].mac_address | ascii_downcase) == ($mac | ascii_downcase) and
    .services.inspector.networks["ssh-egress"].ipv4_address == $eip and
    .networks["mcp-private"].ipam.config[0].gateway == $gateway and
    .networks["ssh-egress"].driver_opts["com.docker.network.bridge.name"] == $bridge and
    (.services.inspector.networks | keys == ["mcp-private", "ssh-egress"])
  ' <<< "$config" >/dev/null || fail 'reviewed multi-host contract mismatch; policy retained'
}

validate_allowlist() {
  [[ ${INSPECTOR_UNIT_EXTERNAL_IPS-} != *$'\n'* &&
     ${INSPECTOR_UNIT_EXTERNAL_IPS-} != *$'\r'* ]] ||
    fail 'external SSH allowlist is ambiguous; policy retained'
  [[ ${#external_ips[@]} -gt 0 ]] || fail 'external SSH allowlist is missing; policy retained'
  # These are the bind sources in the effective configuration used by Inspector,
  # not a second registry path supplied by the unit environment.
  registry_source=$(jq -er '
    [.services.inspector.volumes[] | select(.target == "/run/secrets/host-registry.json")]
    | if length == 1 and .[0].type == "bind" and .[0].read_only == true
      then .[0].source else empty end
  ' <<< "$config") || fail 'mounted host registry is invalid; policy retained'
  secrets_source=$(jq -er '
    [.services.inspector.volumes[] | select(.target == "/run/secrets/inspector-hosts")]
    | if length == 1 and .[0].type == "bind" and .[0].read_only == true
      then .[0].source else empty end
  ' <<< "$config") || fail 'mounted host credentials are invalid; policy retained'
  private_subnet=$(jq -er '.networks["mcp-private"].ipam.config[0].subnet' <<< "$config") ||
    fail 'private network is invalid; policy retained'
  egress_subnet=$(jq -er '.networks["ssh-egress"].ipam.config[0].subnet' <<< "$config") ||
    fail 'egress network is invalid; policy retained'
  if ! timeout 8s python3 "$root/scripts/multi_host_allowlist.py" \
      "$registry_source" "$secrets_source" "$INSPECTOR_UNIT_PRIVATE_GATEWAY" \
      "$private_subnet" "$egress_subnet" "${external_ips[@]}" >/dev/null 2>&1
  then
    fail 'mounted registry and external SSH allowlist are invalid or differ; policy retained'
  fi
}

case ${1:-} in
  policy-start)
    validate_contract
    validate_allowlist
    bash "$root/scripts/multi_network_policy.sh" install "${policy[@]}"
    bash "$root/scripts/multi_network_policy.sh" verify "${policy[@]}"
    ;;
  check)
    validate_contract
    validate_allowlist
    bash "$root/scripts/multi_network_policy.sh" verify "${policy[@]}"
    ;;
  start)
    validate_contract
    validate_allowlist
    bash "$root/scripts/multi_network_policy.sh" verify "${policy[@]}"
    exec "${compose[@]}" up --no-deps --no-build --pull never --exit-code-from inspector inspector
    ;;
  cleanup)
    validate_contract
    ids=$(docker_bounded ps -aq --no-trunc --filter "label=com.docker.compose.project=$INSPECTOR_UNIT_PROJECT" --filter 'label=com.docker.compose.service=inspector') || fail 'cannot list Inspector containers; policy retained'
    for id in $ids; do
      metadata=$(docker_bounded inspect "$id") || fail 'cannot inspect Inspector container; policy retained'
      # A legacy single-host Inspector is never a cleanup target, including
      # when ExecStopPost follows a failed policy check or failed preflight.
      if ! jq -e '.[0].Config.Env | index("INSPECTOR_HOST_MODE=multi")' <<< "$metadata" >/dev/null; then
        jq -e --arg path "$INSPECTOR_UNIT_COMPOSE" '
          .[0] | .Config.Labels["com.docker.compose.project.config_files"] != $path and
          (.NetworkSettings.Networks | keys | all(endswith("_ssh-egress") | not))
        ' <<< "$metadata" >/dev/null || fail "ambiguous Inspector identity ($id); policy retained"
        continue
      fi
      jq -e --arg id "$id" --arg p "$INSPECTOR_UNIT_PROJECT" --arg hash "$expected_hash" --arg image "$expected_image" --arg path "$INSPECTOR_UNIT_COMPOSE" --arg ip "$INSPECTOR_UNIT_PRIVATE_IP" --arg mac "$INSPECTOR_UNIT_PRIVATE_MAC" --arg eip "$INSPECTOR_UNIT_EGRESS_IP" '
        .[0] | .Id == $id and .Config.Labels["com.docker.compose.project"] == $p and
        .Config.Labels["com.docker.compose.service"] == "inspector" and
        .Config.Labels["com.docker.compose.config-hash"] == $hash and
        .Config.Labels["com.docker.compose.project.config_files"] == $path and
        .Image == $image and .HostConfig.RestartPolicy.Name == "no" and
        (.Config.Env | index("INSPECTOR_HOST_MODE=multi")) != null and
        (.State.Running == false or (
          (.NetworkSettings.Networks | keys == [$p + "_mcp-private", $p + "_ssh-egress"]) and
          .NetworkSettings.Networks[$p + "_mcp-private"].IPAddress == $ip and
          (.NetworkSettings.Networks[$p + "_mcp-private"].MacAddress | ascii_downcase) == ($mac | ascii_downcase) and
          .NetworkSettings.Networks[$p + "_ssh-egress"].IPAddress == $eip
        ))
      ' <<< "$metadata" >/dev/null || fail "multi-host container identity mismatch ($id); policy retained"
      if [[ $(jq -r '.[0].State.Running' <<< "$metadata") == true ]]; then
        if ! timeout 12s docker stop --time 5 "$id" >/dev/null; then
          fail "Docker stop failed for $id; policy retained"
        fi
      fi
      state=$(docker_bounded inspect --format '{{.State.Running}}' "$id") || fail "cannot verify stop of $id; policy retained"
      [[ $state == false ]] || fail "Inspector $id remains running; policy retained"
    done
    after=$(docker_bounded ps -aq --no-trunc --filter "label=com.docker.compose.project=$INSPECTOR_UNIT_PROJECT" --filter 'label=com.docker.compose.service=inspector') || fail 'cannot re-list Inspector containers; policy retained'
    [[ $after == "$ids" ]] || fail 'Inspector container set changed during cleanup; policy retained'
    echo 'Multi-host Inspector cleanup verified; policy retained'
    ;;
  *) fail 'expected policy-start, check, start, or cleanup' ;;
esac
