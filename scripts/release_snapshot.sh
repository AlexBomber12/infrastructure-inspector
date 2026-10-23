#!/usr/bin/env bash
# Capture or verify the previous single-host Compose deployment without changing it.
set -euo pipefail

fail() { echo "Rollback snapshot failed: $*" >&2; exit 1; }
label() { docker inspect --format "{{index .Config.Labels \"$2\"}}" "$1"; }
image_id() { docker inspect --format '{{.Image}}' "$1"; }
capture_sources() {
  local service=$1 sources=$2
  local -n args_ref=$3
  local -a files
  local file index
  [[ -n $sources && $sources != '<no value>' ]] || fail "$service Compose file list is empty"
  IFS=, read -r -a files <<< "$sources"
  [[ ${#files[@]} -gt 0 ]] || fail "$service Compose file list is empty"
  printf '%s\n' "$sources" > "$snapshot/$service-file-order"
  printf '%s\n' "${#files[@]}" > "$snapshot/$service-file-count"
  for index in "${!files[@]}"; do
    file=${files[$index]}
    [[ $file == /* && -f $file && ! -L $file ]] || fail "original $service Compose file $((index + 1)) is missing or unsafe"
    args_ref+=(-f "$file")
    cp -- "$file" "$snapshot/$service-file-$(printf '%02d' "$((index + 1))").yaml"
  done
}
check_exports() {
  local name
  while read -r name _; do
    [[ $name == NAME || -z $name ]] && continue
    [[ ! ${!name+x} ]] || fail "unset exported $name before capturing the original configuration"
  done < <(docker compose --env-file "$env_file" "$@" -p "$project" config --variables)
}

mode=${1:-}
snapshot=${2:-}
[[ -n "$snapshot" ]] || fail 'usage: release_snapshot.sh capture SNAPSHOT ENV_FILE INSPECTOR_ID TUNNEL_ID | verify[-current] SNAPSHOT'

# Compose shell exports take precedence over --env-file. Never capture an
# apparently valid config whose values came from an unrecorded shell.
for name in INSPECTOR_IMAGE_ID INSPECTOR_SSH_TARGET INSPECTOR_HOST_LABEL \
  INSPECTOR_SSH_KEY_PATH INSPECTOR_KNOWN_HOSTS_PATH INSPECTOR_DOCKER_SUBNET \
  INSPECTOR_DOCKER_GATEWAY OPENAI_TUNNEL_ID OPENAI_TUNNEL_API_KEY_PATH COMPOSE_PROJECT_NAME; do
  [[ ! ${!name+x} ]] || fail "unset exported $name before using the snapshot"
done

if [[ $mode == capture ]]; then
  [[ $# == 5 ]] || fail 'capture requires snapshot, env file, Inspector ID, and Tunnel ID'
  env_file=$3
  inspector=$4
  tunnel=$5
  [[ -f $env_file && ! -L $env_file ]] || fail 'original Compose env file is missing or unsafe'
  [[ ! -e $snapshot ]] || fail 'snapshot directory already exists'
  umask 077
  mkdir -m 700 -- "$snapshot"
  [[ $(label "$inspector" com.docker.compose.service) == inspector ]] || fail 'Inspector container label mismatch'
  [[ $(label "$tunnel" com.docker.compose.service) == tunnel-client ]] || fail 'Tunnel container label mismatch'
  [[ $(docker inspect --format '{{.State.Running}}' "$inspector") == true ]] || fail 'Inspector is not running'
  [[ $(docker inspect --format '{{.State.Running}}' "$tunnel") == true ]] || fail 'Tunnel is not running'
  project=$(label "$inspector" com.docker.compose.project)
  [[ -n $project && $project != '<no value>' && $(label "$tunnel" com.docker.compose.project) == "$project" ]] || fail 'Compose project mismatch'
  inspector_sources=$(label "$inspector" com.docker.compose.project.config_files)
  tunnel_sources=$(label "$tunnel" com.docker.compose.project.config_files)
  inspector_args=()
  tunnel_args=()
  capture_sources inspector "$inspector_sources" inspector_args
  capture_sources tunnel "$tunnel_sources" tunnel_args
  check_exports "${inspector_args[@]}"
  check_exports "${tunnel_args[@]}"
  cp -- "$env_file" "$snapshot/original.env"
  printf '%s\n' "$project" > "$snapshot/project-name"
  printf '%s\n' "$inspector" > "$snapshot/inspector-container-id"
  printf '%s\n' "$tunnel" > "$snapshot/tunnel-container-id"
  old_image=$(image_id "$inspector")
  [[ $old_image =~ ^sha256:[0-9a-f]{64}$ ]] || fail 'previous image ID is invalid'
  printf '%s\n' "$old_image" > "$snapshot/inspector-image-id"
  docker image inspect "$old_image" >/dev/null || fail 'previous image is unavailable'
  docker compose --env-file "$env_file" "${inspector_args[@]}" -p "$project" config --format json > "$snapshot/effective.json" || fail 'original Compose configuration cannot be resolved'
  inspector_hash=$(label "$inspector" com.docker.compose.config-hash)
  printf '%s\n' "$inspector_hash" > "$snapshot/inspector-config-hash"
  tunnel_hash=$(label "$tunnel" com.docker.compose.config-hash)
  resolved=$(docker compose --env-file "$env_file" "${inspector_args[@]}" -p "$project" config --hash inspector) || fail 'cannot hash Inspector configuration'
  [[ $resolved == "inspector $inspector_hash" ]] || fail 'Inspector configuration differs from the running container'
  resolved=$(docker compose --env-file "$env_file" "${tunnel_args[@]}" -p "$project" config --hash tunnel-client) || fail 'cannot hash Tunnel configuration'
  [[ $resolved == "tunnel-client $tunnel_hash" ]] || fail 'Tunnel configuration differs from the running container'
  resolved=$(docker compose --env-file "$env_file" "${inspector_args[@]}" -p "$project" config --hash tunnel-client) || fail 'cannot hash Tunnel configuration in Inspector source files'
  [[ $resolved == "tunnel-client $tunnel_hash" ]] || fail 'Inspector source files cannot reproduce the running Tunnel configuration'
  printf 'services:\n  inspector:\n    image: %s\n    pull_policy: never\n' "$old_image" > "$snapshot/rollback-image.yaml"
  (cd "$snapshot" && sha256sum original.env effective.json rollback-image.yaml project-name inspector-container-id inspector-image-id inspector-config-hash tunnel-container-id inspector-file-order inspector-file-count inspector-file-*.yaml tunnel-file-order tunnel-file-count tunnel-file-*.yaml > SHA256SUMS)
  echo 'Rollback snapshot captured and checked against running Compose labels'
elif [[ $mode == verify || $mode == verify-current ]]; then
  [[ $# == 2 && -d $snapshot && ! -L $snapshot ]] || fail 'snapshot directory is missing or unsafe'
  (cd "$snapshot" && sha256sum --status -c SHA256SUMS) || fail 'snapshot files are missing or changed'
  for service in inspector tunnel; do
    count=$(cat "$snapshot/$service-file-count")
    [[ $count =~ ^[1-9][0-9]*$ ]] || fail "$service snapshot Compose file count is invalid"
    for ((index=1; index<=count; index++)); do
      [[ -f $snapshot/$service-file-$(printf '%02d' "$index").yaml ]] || fail "$service snapshot Compose file $index is missing"
    done
  done
  project=$(cat "$snapshot/project-name")
  tunnel=$(cat "$snapshot/tunnel-container-id")
  old_image=$(cat "$snapshot/inspector-image-id")
  [[ $old_image =~ ^sha256:[0-9a-f]{64}$ && $(docker image inspect --format '{{.Id}}' "$old_image") == "$old_image" ]] || fail 'previous image is unavailable or changed'
  [[ $(docker inspect --format '{{.State.Running}}' "$tunnel") == true && $(label "$tunnel" com.docker.compose.project) == "$project" && $(label "$tunnel" com.docker.compose.service) == tunnel-client ]] || fail 'Tunnel container identity changed'
  python3 - "$snapshot/effective.json" "$project" <<'PY' || fail 'saved effective Compose configuration is invalid'
import json, sys
with open(sys.argv[1], encoding="utf-8") as source:
    config = json.load(source)
assert config["name"] == sys.argv[2]
assert {"inspector", "tunnel-client"} <= set(config["services"])
PY
  docker compose -f "$snapshot/effective.json" -f "$snapshot/rollback-image.yaml" -p "$project" config --quiet || fail 'rollback Compose configuration is invalid'
  if [[ $mode == verify-current ]]; then
    inspector=$(cat "$snapshot/inspector-container-id")
    expected_hash=$(cat "$snapshot/inspector-config-hash")
    [[ $(docker inspect --format '{{.State.Running}}' "$inspector" 2>/dev/null) == true \
      && $(image_id "$inspector") == "$old_image" \
      && $(label "$inspector" com.docker.compose.project) == "$project" \
      && $(label "$inspector" com.docker.compose.service) == inspector \
      && $(label "$inspector" com.docker.compose.config-hash) == "$expected_hash" \
      && $(docker compose -f "$snapshot/effective.json" -f "$snapshot/rollback-image.yaml" -p "$project" ps -q inspector) == "$inspector" ]] || fail 'captured Inspector is no longer the current deployment'
  fi
  echo 'Rollback snapshot is ready'
else
  fail 'expected capture, verify, or verify-current'
fi
