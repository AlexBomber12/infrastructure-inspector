# Inspector 0.3.0 single-host release

Production 0.3.0 is operator-reported; CI does not attest the live host or
Tunnel. The release image ID, its embedded source commit, and the reviewed
**deployment checkout** commit are three distinct identities. Keep the first
two in a private release record. Never derive the expected IDs from the
candidate image's own labels or from a mutable tag. The checkout supplies the
reviewed `compose.yaml` and preflight; its local `inspector/` source is not a
production build input.

This procedure changes only Inspector. Do not deploy from this repository
without separate operator authorization. Never copy host addresses, credentials,
private configuration, or a live image ID into Git.

## 1. Capture the running deployment

Use the existing deployment's exact Compose invocation to identify its running
Inspector and Tunnel container IDs. Identify the env file that supplied the
old Compose interpolation values. If the old invocation used shell exports,
move those values into a private env file and unset the exports first. The
capture fails unless each service's own resolved hash matches its live
container and the frozen configuration can reproduce both. It reads each
container's Compose labels to recover its Compose file **order** and the
project name; the file lists can differ after Inspector-only recreation. It
refuses missing files, including a temporary override. It saves private copies of those files, the
env file, the previous image ID, container identities, checksums, and a frozen
resolved Compose configuration. The snapshot directory must be new and private.
A failed capture leaves an unusable partial directory; discard it and retry
with a new path after fixing the cause.

```sh
set -euo pipefail
umask 077
backup_dir=/private/inspector-snapshot-UNIQUE
old_env=/private/old-deployment.env
old_inspector=REPLACE_WITH_RUNNING_INSPECTOR_CONTAINER_ID
tunnel_before=REPLACE_WITH_RUNNING_TUNNEL_CONTAINER_ID
bash scripts/release_snapshot.sh capture "$backup_dir" "$old_env" \
  "$old_inspector" "$tunnel_before"
bash scripts/release_snapshot.sh verify-current "$backup_dir"
```

The capture must run while the previous Inspector is still running. If an
original file or env value cannot be recovered, or the service hashes differ,
stop before recreation. Do not substitute the candidate configuration for the
old deployment. Retain the old image locally; readiness checks it by full ID.
`verify-current` also requires the captured Inspector to remain the running
container in the recorded project, with the same image and Compose hash. Use
it before deployment; use `verify` for rollback after Inspector has changed.
The snapshot is a private recovery artifact and can include resolved operator
values. Protect and retain it until the deployment is accepted.

## 2. Validate the candidate

Use a clean, reviewed deployment checkout. Copy its single-host `compose.yaml`
to a permanent operator-owned path outside Git. Create one permanent private
`.env` from `.env.example` and replace every example value, including
`INSPECTOR_IMAGE_ID`, SSH target and label, secret paths, private subnet and
gateway, and Tunnel ID. Use absolute paths for secret files. Compose
interpolation reads the explicit `--env-file`; container `env_file` is not a
substitute. No temporary override is needed for the candidate.

Obtain `image_id` and `image_revision` from an independently verified release
record. Obtain `deployment_revision` from the reviewed deployment commit. The
preflight requires the current checkout to equal that deployment revision and
be clean; separately, it checks the exact local image ID and its embedded
source revision. It checks mandatory single-host settings, mounts, network,
Tunnel contract, non-root/read-only settings, and an isolated SSH-command
probe. It does not contact production SSH or read secret contents. The
snapshot check ensures rollback remains possible before any mutation.

The deployment operator needs Docker daemon access, but does not need host
traversal permission on root-owned secret directories. Preflight uses the
verified local image in short-lived, no-network, read-only probes. It checks
each source entry without following a final symlink, then opens the exact
read-only file bind as the configured Inspector or Tunnel UID/GID and compares
file identities. The metadata probe runs as root with all capabilities dropped
and sees only the source's immediate parent directory; it never reads credential
bytes. A secret parent must be traversable by that constrained root process.
Failure to inspect or open any required mount stops the release before container
recreation. Docker daemon access is already privileged; limit it to trusted
deployment operators.

```sh
set -euo pipefail
unset INSPECTOR_IMAGE_ID INSPECTOR_SSH_TARGET INSPECTOR_HOST_LABEL \
  INSPECTOR_SSH_KEY_PATH INSPECTOR_KNOWN_HOSTS_PATH \
  INSPECTOR_DOCKER_SUBNET INSPECTOR_DOCKER_GATEWAY \
  OPENAI_TUNNEL_ID OPENAI_TUNNEL_API_KEY_PATH COMPOSE_PROJECT_NAME
image_id=REPLACE_WITH_VERIFIED_FULL_SHA256_IMAGE_ID
image_revision=REPLACE_WITH_VERIFIED_IMAGE_SOURCE_COMMIT_SHA
deployment_revision=REPLACE_WITH_REVIEWED_DEPLOYMENT_COMMIT_SHA
compose_file=/private/deployment/compose.yaml
env_file=/private/deployment/.env
project_name=$(cat "$backup_dir/project-name")
bash scripts/release_snapshot.sh verify-current "$backup_dir"
python3 scripts/release_preflight.py \
  --image-id "$image_id" --revision "$image_revision" \
  --deployment-revision "$deployment_revision" \
  --compose-file "$compose_file" --env-file "$env_file" \
  --project-name "$project_name"
```

Preflight rejects exported Compose interpolation variables. Keep them unset
for the deploy and rollback commands too. If the checkout, image, candidate,
or snapshot fails validation, stop and investigate. The prior source revision
need not equal the deployment revision; a stale local source tree cannot build
or replace the verified image.

## 3. Replace only Inspector and verify

After explicit operator authorization, recheck readiness and use the **same**
candidate files, project, and image ID. `--no-deps` leaves the Tunnel alone;
`--no-build --pull never` prevents stale builds and registry substitution.

```sh
set -euo pipefail
unset INSPECTOR_IMAGE_ID INSPECTOR_SSH_TARGET INSPECTOR_HOST_LABEL \
  INSPECTOR_SSH_KEY_PATH INSPECTOR_KNOWN_HOSTS_PATH \
  INSPECTOR_DOCKER_SUBNET INSPECTOR_DOCKER_GATEWAY \
  OPENAI_TUNNEL_ID OPENAI_TUNNEL_API_KEY_PATH COMPOSE_PROJECT_NAME
bash scripts/release_snapshot.sh verify-current "$backup_dir"
python3 scripts/release_preflight.py \
  --image-id "$image_id" --revision "$image_revision" \
  --deployment-revision "$deployment_revision" \
  --compose-file "$compose_file" --env-file "$env_file" \
  --project-name "$project_name"
docker compose --env-file "$env_file" -f "$compose_file" -p "$project_name" \
  up -d --no-deps --no-build --pull never inspector
new_inspector=$(docker compose --env-file "$env_file" -f "$compose_file" \
  -p "$project_name" ps -q inspector)
test -n "$new_inspector"
test "$(docker inspect --format '{{.Image}}' "$new_inspector")" = "$image_id"
test "$(docker compose --env-file "$env_file" -f "$compose_file" \
  -p "$project_name" ps -q tunnel-client)" = "$tunnel_before"
```

Inspect the new container's UID/GID, read-only root, dropped capabilities,
no-new-privileges, secret mounts, private network, and absence of published
ports and Docker socket. Confirm the Tunnel remains connected. Through the
existing MCP access path, call all six tools: `inspector_status`, `list_hosts`,
`list_checks`, `inspect_server`, `inspect`, and `inspect_batch`. Include real
SSH `identity` and `uptime` diagnostics plus rejection of an unknown check
and host. Check result status, host label, timestamp, and non-root identity.
Running state or empty logs is not evidence of diagnostic success. Keep host
output and credentials out of public CI and PR logs.

## 4. Roll back on any failed verification

The saved `effective.json` is the *old resolved configuration*, not a copy of
the candidate. Its final private image override selects the recorded old
image ID even if the old Compose source used a mutable tag. Verify readiness
again, recreate **only** Inspector, then prove the restored image and unchanged
Tunnel identity. A failed check is a stop condition; investigate rather than
claiming a successful rollback.

```sh
set -euo pipefail
unset INSPECTOR_IMAGE_ID INSPECTOR_SSH_TARGET INSPECTOR_HOST_LABEL \
  INSPECTOR_SSH_KEY_PATH INSPECTOR_KNOWN_HOSTS_PATH \
  INSPECTOR_DOCKER_SUBNET INSPECTOR_DOCKER_GATEWAY \
  OPENAI_TUNNEL_ID OPENAI_TUNNEL_API_KEY_PATH COMPOSE_PROJECT_NAME
bash scripts/release_snapshot.sh verify "$backup_dir"
old_image_id=$(cat "$backup_dir/inspector-image-id")
project_name=$(cat "$backup_dir/project-name")
tunnel_before=$(cat "$backup_dir/tunnel-container-id")
docker compose -f "$backup_dir/effective.json" \
  -f "$backup_dir/rollback-image.yaml" -p "$project_name" \
  up -d --no-deps --no-build --pull never inspector
restored=$(docker compose -f "$backup_dir/effective.json" \
  -f "$backup_dir/rollback-image.yaml" -p "$project_name" ps -q inspector)
test -n "$restored"
test "$(docker inspect --format '{{.Image}}' "$restored")" = "$old_image_id"
test "$(docker compose -f "$backup_dir/effective.json" \
  -f "$backup_dir/rollback-image.yaml" -p "$project_name" \
  ps -q tunnel-client)" = "$tunnel_before"
```

Inspect restored runtime restrictions and networks, then repeat real legacy
MCP-to-SSH calls through the Tunnel. The disposable rollback test covers
container replacement and restoration; it cannot prove the live Tunnel,
credentials, dispatcher, host utilities, or production network policy.
