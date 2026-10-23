#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
fixture=$(mktemp -d)
project="inspector-rollback-$$"
cleanup() {
  docker compose -p "$project" -f "$fixture/base.yaml" -f "$fixture/override.yaml" down --remove-orphans >/dev/null 2>&1 || true
  docker compose -p "${project}-other" -f "$fixture/base.yaml" -f "$fixture/override.yaml" down --remove-orphans >/dev/null 2>&1 || true
  rm -rf -- "$fixture"
}
trap cleanup EXIT
old_image=$(docker image inspect --format '{{.Id}}' infrastructure-inspector:ci)
new_image=$(docker image inspect --format '{{.Id}}' infrastructure-inspector-test:ci)
test "$old_image" != "$new_image"
printf 'TEST_LABEL=original\n' > "$fixture/original.env"
cat > "$fixture/base.yaml" <<EOF_BASE
name: fixture-default
services:
  inspector:
    image: $old_image
    pull_policy: never
    command: ["python", "-c", "import time;time.sleep(3600)"]
    user: "65533:65533"
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    environment:
      INSPECTOR_HOST_LABEL: base
    networks: [private]
  tunnel-client:
    image: $old_image
    pull_policy: never
    command: ["python", "-c", "import time;time.sleep(3600)"]
    user: "65532:65532"
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    networks: [private]
networks:
  private:
    internal: true
EOF_BASE
cat > "$fixture/override.yaml" <<'EOF_OVERRIDE'
services:
  inspector:
    environment:
      INSPECTOR_HOST_LABEL: ${TEST_LABEL:?Required}
EOF_OVERRIDE
docker compose --env-file "$fixture/original.env" -f "$fixture/base.yaml" -f "$fixture/override.yaml" -p "$project" up -d --no-build --pull never inspector tunnel-client >/dev/null
old_container=$(docker compose --env-file "$fixture/original.env" -f "$fixture/base.yaml" -f "$fixture/override.yaml" -p "$project" ps -q inspector)
tunnel=$(docker compose --env-file "$fixture/original.env" -f "$fixture/base.yaml" -f "$fixture/override.yaml" -p "$project" ps -q tunnel-client)
tunnel_hash=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.config-hash"}}' "$tunnel")
# Missing original override and mismatched project must fail before recreation.
if bash scripts/release_snapshot.sh capture "$fixture/missing-env" "$fixture/not-present.env" "$old_container" "$tunnel" >"$fixture/missing-env.log" 2>&1; then
  echo 'Missing original env file passed snapshot capture' >&2; exit 1
fi
rg -q 'env file is missing' "$fixture/missing-env.log"
mv "$fixture/override.yaml" "$fixture/override.saved"
if bash scripts/release_snapshot.sh capture "$fixture/missing-snapshot" "$fixture/original.env" "$old_container" "$tunnel" >"$fixture/missing-override.log" 2>&1; then
  echo 'Missing original override passed snapshot capture' >&2; exit 1
fi
rg -q 'original inspector Compose file 2 is missing' "$fixture/missing-override.log"
mv "$fixture/override.saved" "$fixture/override.yaml"
other_project="${project}-other"
docker compose --env-file "$fixture/original.env" -f "$fixture/base.yaml" -f "$fixture/override.yaml" -p "$other_project" up -d --no-build --pull never inspector tunnel-client >/dev/null
other_tunnel=$(docker compose --env-file "$fixture/original.env" -f "$fixture/base.yaml" -f "$fixture/override.yaml" -p "$other_project" ps -q tunnel-client)
if bash scripts/release_snapshot.sh capture "$fixture/wrong-project" "$fixture/original.env" "$old_container" "$other_tunnel" >"$fixture/wrong-project.log" 2>&1; then
  echo 'Wrong Compose project passed snapshot capture' >&2; exit 1
fi
rg -q 'Compose project mismatch' "$fixture/wrong-project.log"
docker compose --env-file "$fixture/original.env" -f "$fixture/base.yaml" -f "$fixture/override.yaml" -p "$other_project" down --remove-orphans >/dev/null
mkdir "$fixture/wrapper"
cat > "$fixture/wrapper/docker" <<'EOF_DOCKER'
#!/usr/bin/env bash
if [[ ${1:-} == inspect && ${3:-} == *com.docker.compose.project.config_files* ]]; then
  "$DOCKER_REAL" "$@" | awk -F, '{print $2 "," $1}'
else
  exec "$DOCKER_REAL" "$@"
fi
EOF_DOCKER
chmod +x "$fixture/wrapper/docker"
if DOCKER_REAL=$(command -v docker) PATH="$fixture/wrapper:$PATH" \
  bash scripts/release_snapshot.sh capture "$fixture/wrong-order" \
  "$fixture/original.env" "$old_container" "$tunnel" >"$fixture/wrong-order.log" 2>&1; then
  echo 'Wrong Compose file order passed snapshot capture' >&2; exit 1
fi
rg -q 'configuration differs from the running container' "$fixture/wrong-order.log"
bash scripts/release_snapshot.sh capture "$fixture/snapshot" "$fixture/original.env" "$old_container" "$tunnel"
bash scripts/release_snapshot.sh verify "$fixture/snapshot"
bash scripts/release_snapshot.sh verify-current "$fixture/snapshot"
# A reversed source order does not reproduce the running Inspector config hash.
reversed=$(docker compose --env-file "$fixture/original.env" -f "$fixture/override.yaml" -f "$fixture/base.yaml" -p "$project" config --hash inspector | awk '{print $2}')
actual=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.config-hash"}}' "$old_container")
test "$reversed" != "$actual"
# Tampering with or omitting a saved file fails readiness.
mv "$fixture/snapshot/inspector-file-02.yaml" "$fixture/snapshot/inspector-file-02.missing"
if bash scripts/release_snapshot.sh verify "$fixture/snapshot" >"$fixture/incomplete.log" 2>&1; then
  echo 'Incomplete snapshot passed readiness' >&2; exit 1
fi
rg -q 'snapshot files are missing or changed' "$fixture/incomplete.log"
mv "$fixture/snapshot/inspector-file-02.missing" "$fixture/snapshot/inspector-file-02.yaml"
# An unavailable previous image ID is rejected without changing containers.
cp -a "$fixture/snapshot" "$fixture/unavailable"
printf 'sha256:%064d\n' 0 > "$fixture/unavailable/inspector-image-id"
(cd "$fixture/unavailable" && sha256sum original.env effective.json rollback-image.yaml project-name inspector-container-id inspector-image-id inspector-config-hash tunnel-container-id inspector-file-order inspector-file-count inspector-file-*.yaml tunnel-file-order tunnel-file-count tunnel-file-*.yaml > SHA256SUMS)
if bash scripts/release_snapshot.sh verify "$fixture/unavailable" >"$fixture/unavailable.log" 2>&1; then
  echo 'Unavailable old image passed readiness' >&2; exit 1
fi
rg -q 'previous image is unavailable' "$fixture/unavailable.log"
# Replace only Inspector, simulate failed post-deployment verification, then roll back.
cat > "$fixture/candidate.yaml" <<EOF_CANDIDATE
services:
  inspector:
    image: $new_image
    environment:
      INSPECTOR_HOST_LABEL: wrong-host
EOF_CANDIDATE
docker compose --env-file "$fixture/original.env" -f "$fixture/base.yaml" -f "$fixture/override.yaml" -f "$fixture/candidate.yaml" -p "$project" up -d --no-deps --no-build --pull never inspector >/dev/null
candidate=$(docker compose --env-file "$fixture/original.env" -f "$fixture/base.yaml" -f "$fixture/override.yaml" -f "$fixture/candidate.yaml" -p "$project" ps -q inspector)
test "$(docker inspect --format '{{.Image}}' "$candidate")" = "$new_image"
test "$(docker compose --env-file "$fixture/original.env" -f "$fixture/base.yaml" -f "$fixture/override.yaml" -p "$project" ps -q tunnel-client)" = "$tunnel"
bash scripts/release_snapshot.sh capture "$fixture/candidate-snapshot" "$fixture/original.env" "$candidate" "$tunnel"
bash scripts/release_snapshot.sh verify "$fixture/candidate-snapshot"
bash scripts/release_snapshot.sh verify-current "$fixture/candidate-snapshot"
if bash scripts/release_snapshot.sh verify-current "$fixture/snapshot" >"$fixture/stale-inspector.log" 2>&1; then
  echo 'Replaced Inspector passed current-deployment verification' >&2; exit 1
fi
rg -q 'captured Inspector is no longer the current deployment' "$fixture/stale-inspector.log"
# A wrong host label stands in for a failed MCP post-deployment verification.
if docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$candidate" | rg -q '^INSPECTOR_HOST_LABEL=original$'; then
  echo 'Expected candidate verification failure' >&2; exit 1
fi
bash scripts/release_snapshot.sh verify "$fixture/snapshot"
docker compose -f "$fixture/snapshot/effective.json" -f "$fixture/snapshot/rollback-image.yaml" -p "$project" up -d --no-deps --no-build --pull never inspector >/dev/null
restored=$(docker compose -f "$fixture/snapshot/effective.json" -f "$fixture/snapshot/rollback-image.yaml" -p "$project" ps -q inspector)
test "$(docker inspect --format '{{.Image}}' "$restored")" = "$old_image"
test "$(docker inspect --format '{{.Config.User}}' "$restored")" = '65533:65533'
test "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$restored")" = true
test "$(docker inspect --format '{{.HostConfig.CapDrop}}' "$restored")" = '[ALL]'
docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$restored" | rg -q '^INSPECTOR_HOST_LABEL=original$'
test "$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$restored")" = "$project"
test "$(docker inspect --format '{{index .Config.Labels "com.docker.compose.config-hash"}}' "$tunnel")" = "$tunnel_hash"
test "$(docker compose -f "$fixture/snapshot/effective.json" -f "$fixture/snapshot/rollback-image.yaml" -p "$project" ps -q tunnel-client)" = "$tunnel"
docker inspect --format '{{json .NetworkSettings.Networks}}' "$restored" | python3 -c 'import json,sys; x=json.load(sys.stdin); assert len(x)==1 and next(iter(x)).endswith("_private")'
test "$(docker network inspect --format '{{.Internal}}' "${project}_private")" = true
bash scripts/release_snapshot.sh capture "$fixture/after-rollback-snapshot" "$fixture/original.env" "$restored" "$tunnel"
bash scripts/release_snapshot.sh verify "$fixture/after-rollback-snapshot"
echo 'Disposable Inspector replacement and rollback passed'
