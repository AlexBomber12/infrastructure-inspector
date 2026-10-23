# Inspector 0.3.0 single-host deployment

The observed production Inspector is 0.3.0; this is operator-reported context,
not a CI assertion about the live host. Keep its actual image ID in the private
operator release record, outside this public repository. The
current deployment needed a temporary Compose override for its SSH target and
host label. This procedure moves those values into one permanent, private
Compose env file. It changes only the Inspector container. Do not copy the
observed address, target, or credentials into the repository.

## Inspect and prepare

Use a reviewed checkout containing this `compose.yaml` and preflight on the
deployment host. The checkout's `inspector/` source is not used to build the
production image. Preserve the existing tunnel container, network, and secrets.
Choose an operator-owned directory outside Git for `compose.yaml` and `.env`;
copy the reviewed Compose file there. Copy `.env.example` there as `.env`, then
replace *every* example value with the intended deployment values, including
`INSPECTOR_IMAGE_ID`, `INSPECTOR_SSH_TARGET`, `INSPECTOR_HOST_LABEL`, all three
secret file paths, network subnet/gateway, and Tunnel ID. The image ID must be
the full locally available ID of the tested 0.3.0 image. Keep the env file
private and use absolute paths for secret files. Docker Compose interpolates
these variables from the explicit `--env-file`; a container `env_file` would
not supply values for Compose interpolation. Do not use a temporary override.

Before changing anything, record the running Inspector container ID, image ID,
effective Compose configuration, private env file, and the tunnel container ID
in an operator-owned backup directory. Capture the *current* configuration even
if it used an override. Keep the old image locally (or `docker image save` it)
and verify that `docker image inspect` still resolves the saved ID. Preserve the
old configuration files exactly. Do not use a mutable tag as the rollback
identity. If the reported image ID differs from the live one, investigate and
use the verified live state; do not assume the report is current.

```sh
umask 077
backup_dir=/private/inspector-backup
mkdir -p "$backup_dir"
# Set compose_file and env_file to the permanent candidate files.
compose_file=/private/deployment/compose.yaml
env_file=/private/deployment/.env
# Obtain these IDs from the existing deployment's exact Compose invocation.
old_container=REPLACE_WITH_VERIFIED_INSPECTOR_CONTAINER_ID
tunnel_before=REPLACE_WITH_VERIFIED_TUNNEL_CONTAINER_ID
test -n "$old_container"
docker inspect --format '{{.Image}}' "$old_container" > "$backup_dir/inspector-image-id"
docker image inspect "$(cat "$backup_dir/inspector-image-id")" >/dev/null
test -n "$tunnel_before"
project_name=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$old_container")
test -n "$project_name"
test "$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$tunnel_before")" = "$project_name"
printf '%s\n' "$project_name" > "$backup_dir/project-name"
# Save the existing deployment's original Compose, env, and override files here.
# Separately retain the candidate compose_file and env_file for deployment.
```

Do not treat candidate configuration as a backup of the old deployment. If the
old deployment used an override, save it and the exact old Compose invocation.
Verify both recorded container IDs with `docker inspect` independently.

## Validate before recreation

Take the full expected image ID and revision SHA from the independently verified
release record; do not derive expected values from the mutable image tag or
from the local checkout. Confirm that this exact image is available on the
deployment Docker Engine. Use a reviewed checkout whose Git history contains
the release revision as an ancestor. Provide both values to the preflight. The preflight checks Compose interpolation, required
single-host values, safe nonempty secret bind files, private network, tunnel
contract, non-root/read-only runtime, no build path, local image identity,
version/revision labels, and an isolated SSH-command probe. It does not read
secret contents, contact production SSH, or change containers. It compares the
candidate's effective Compose configuration with the reviewed template while
allowing operator-specific values. A missing or blank SSH target stops before
any recreation. The image ID in `.env` must match `--image-id` exactly.
The recorded project name must match both running containers and the effective
candidate configuration; `-p` preserves it even if the old deployment used a
project override.
Compose gives exported shell variables priority over `--env-file`. Clear the
listed interpolation names and `COMPOSE_PROJECT_NAME` in every shell used for
validation, deployment, or rollback. Preflight rejects them if exported.

```sh
unset INSPECTOR_IMAGE_ID INSPECTOR_SSH_TARGET INSPECTOR_HOST_LABEL \
  INSPECTOR_SSH_KEY_PATH INSPECTOR_KNOWN_HOSTS_PATH \
  INSPECTOR_DOCKER_SUBNET INSPECTOR_DOCKER_GATEWAY \
  OPENAI_TUNNEL_ID OPENAI_TUNNEL_API_KEY_PATH COMPOSE_PROJECT_NAME
image_id=REPLACE_WITH_VERIFIED_FULL_SHA256_IMAGE_ID
revision=REPLACE_WITH_VERIFIED_FULL_SOURCE_COMMIT_SHA
project_name=$(cat "$backup_dir/project-name")
test "$(docker image inspect --format '{{.Id}}' "$image_id")" = "$image_id"
test "$(sed -n 's/^INSPECTOR_IMAGE_ID=//p' "$env_file")" = "$image_id"
python3 scripts/release_preflight.py --revision "$revision" --image-id "$image_id" \
  --compose-file "$compose_file" --env-file "$env_file" --project-name "$project_name"
```

If the preflight fails, stop. Resolve any discrepancy between checkout, image labels,
Compose, and the running container before deployment. The preflight cannot
establish that the live dispatcher, SSH account, target utilities, or Tunnel
actually work; use the smoke calls below.

## Deploy and verify

Only after the operator authorizes the prepared change, use the *same* Compose
and env files. `--no-deps` prevents tunnel recreation. `--no-build` and
`--pull never` prevent source rebuilds or registry substitution. Compose uses
the verified immutable image ID from `.env`.

```sh
unset INSPECTOR_IMAGE_ID INSPECTOR_SSH_TARGET INSPECTOR_HOST_LABEL \
  INSPECTOR_SSH_KEY_PATH INSPECTOR_KNOWN_HOSTS_PATH \
  INSPECTOR_DOCKER_SUBNET INSPECTOR_DOCKER_GATEWAY \
  OPENAI_TUNNEL_ID OPENAI_TUNNEL_API_KEY_PATH COMPOSE_PROJECT_NAME
project_name=$(cat "$backup_dir/project-name")
docker compose --env-file "$env_file" -f "$compose_file" -p "$project_name" \
  up -d --no-deps --no-build --pull never inspector
new_container=$(docker compose --env-file "$env_file" -f "$compose_file" -p "$project_name" ps -q inspector)
test -n "$new_container"
test "$(docker inspect --format '{{.Image}}' "$new_container")" = "$image_id"
test "$(docker compose --env-file "$env_file" -f "$compose_file" -p "$project_name" ps -q tunnel-client)" = "$tunnel_before"
```

Inspect the new container's UID/GID, read-only root, dropped capabilities,
no-new-privileges, mounts, networks, and absence of published ports and Docker
socket. Verify the Tunnel remains connected. Through the existing MCP access
path, call `inspector_status`, `list_hosts`, `list_checks`, `inspect_server`,
`inspect`, and `inspect_batch`; include real `identity` and `uptime` SSH
checks and rejection of an unknown check and host. Confirm successful result
status, expected host label, timestamps, and non-root identity. Running state
or empty logs alone are not evidence of successful diagnostics. Never put host
output or credentials in public CI or PR logs. CI exercises a disposable SSH
stack; it cannot verify the production Tunnel or host.

## Roll back on any failed verification

Restore the exact backed-up Compose and env files (and any original override
file), confirm the old image ID remains available, then recreate **only**
Inspector with the old invocation and `--no-deps --no-build --pull never`.
Append a private final Compose override that selects the recorded old image ID,
so an old mutable tag cannot select a different image. This override exists
only for rollback; routine deployment uses the permanent env file alone.
For the normal permanent single-file configuration:

```sh
unset INSPECTOR_IMAGE_ID INSPECTOR_SSH_TARGET INSPECTOR_HOST_LABEL \
  INSPECTOR_SSH_KEY_PATH INSPECTOR_KNOWN_HOSTS_PATH \
  INSPECTOR_DOCKER_SUBNET INSPECTOR_DOCKER_GATEWAY \
  OPENAI_TUNNEL_ID OPENAI_TUNNEL_API_KEY_PATH COMPOSE_PROJECT_NAME
old_image_id=$(cat "$backup_dir/inspector-image-id")
project_name=$(cat "$backup_dir/project-name")
docker image inspect "$old_image_id" >/dev/null
printf 'services:\n  inspector:\n    image: %s\n' "$old_image_id" > "$backup_dir/rollback-image.yaml"
cp -p "$backup_dir/compose.yaml" "$backup_dir/.env" /private/deployment/
docker compose --env-file /private/deployment/.env \
  -f /private/deployment/compose.yaml -f "$backup_dir/rollback-image.yaml" -p "$project_name" \
  up -d --no-deps --no-build --pull never inspector
rolled_back=$(docker compose --env-file /private/deployment/.env \
  -f /private/deployment/compose.yaml -f "$backup_dir/rollback-image.yaml" -p "$project_name" ps -q inspector)
test "$(docker inspect --format '{{.Image}}' "$rolled_back")" = "$old_image_id"
test "$(docker compose --env-file /private/deployment/.env \
  -f /private/deployment/compose.yaml -f "$backup_dir/rollback-image.yaml" \
  -p "$project_name" ps -q tunnel-client)" = "$tunnel_before"
```

For a prior deployment that used a temporary override, use its backed-up
original files and exact Compose invocation, appending the rollback image
override last. Verify legacy MCP-to-SSH
checks through the Tunnel after rollback. Stop and investigate if the old image
or configuration is unavailable; an unverified tag is not a rollback.
