# Inspector 0.3.0 single-host pilot runbook

This is an operator procedure for a future, explicitly authorized pilot. This
PR does not authorize deployment. Production 0.2.0 and its OpenAI Tunnel stay
running until the operator approves the steps marked **production** below.

## Release contract

- Source: one full Git commit SHA from this PR after review and merge.
- Application: MCP version `0.3.0`; image tag
  `infrastructure-inspector:0.3.0`; OCI version label `0.3.0`; OCI revision
  label equal to the source SHA.
- Image identity: the full `sha256:` image ID recorded from `docker image
  inspect`; a tag alone is not an identity. Record a registry digest as well
  if the image is transferred through a registry. The base Python image and
  OpenAI Tunnel image are pinned by digest in source.
- Dispatcher: the exact `host/sg-audit-dispatch.py` bytes in the release
  commit, independently installed as the SSH account's ForceCommand.
- Deployment: `compose.yaml` only, with existing single-host `.env` values.
  Do not use `compose.multi.yaml`, `INSPECTOR_HOST_MODE=multi`, or an SSH egress
  bridge for this pilot.

The pinned base image and fully versioned Python wheel lock constrain build
inputs; installation rejects source distributions and unlisted dependencies.
The image build normalizes root-owned application modules and their directory
permissions. Restrictive source checkouts, including files staged with mode
`0600` under `umask 077`, are supported. CI builds such a context with both
BuildKit and the legacy builder, then runs the release import probe as UID/GID
65533:65533 with no network and a read-only filesystem.
The full image ID is the final artifact identity because Debian package indexes
and wheel repositories remain mutable.
Retain the verified artifact for deployment and rollback; rebuilding the same
commit later is not guaranteed to produce the same bytes. No image is
published or deployed automatically.

## 1. Local release preparation (safe for CI or a disposable workstation)

Start from a clean checkout of the reviewed release commit. Use a dedicated
directory outside the public repository for local `.env`, staged dispatcher,
and recorded image IDs. Never paste secret contents into logs or PR comments.
The production configuration is operator-owned and must not be copied into CI.

```sh
release_revision=$(git rev-parse HEAD)
test -z "$(git status --porcelain)"
bash scripts/ci.sh
docker build --pull=false --build-arg SOURCE_REVISION="$release_revision" \
  -f inspector/Dockerfile -t infrastructure-inspector:0.3.0 inspector
release_image_id=$(docker image inspect --format '{{.Id}}' infrastructure-inspector:0.3.0)
printf 'revision=%s image=%s\n' "$release_revision" "$release_image_id"
```

For an operator workstation with the deployment `.env` and a **locally staged**
copy of the intended dispatcher, run this local-only preflight. It invokes
`docker compose config`, inspects the local image, and runs an isolated Python
probe with `--network none`; it does not read secret contents, connect to SSH,
restart containers, or modify the host. A failed check stops the upgrade.
It compares the effective deployment Compose runtime settings with the approved
single-host Compose file in the clean release commit. Operator-specific paths,
SSH target and label, Tunnel ID, Compose project location, and private subnet
and gateway may differ; missing service wiring or weaker isolation fails.

```sh
python3 scripts/release_preflight.py \
  --revision "$release_revision" --image-id "$release_image_id" \
  --compose-file /path/to/private/compose.yaml \
  --env-file /path/to/private/.env \
  --dispatcher /path/to/staged/sg-audit-dispatch.py
```

The staged dispatcher must have the same SHA-256 as the reviewed release file.
An old dispatcher fails this preflight. The separate unit, MCP, and disposable
SSH tests establish that all four legacy commands still work and unknown
commands are denied. The preflight does not attest the live target's SSH
configuration or installed utilities.

## 2. Production preparation (explicit human authorization required)

Confirm the pilot's approved host, maintenance window, operator access, and
rollback owner. Confirm the current Tunnel and 0.2.0 tools work before any
change. Confirm the target account remains unprivileged and its `sshd`
configuration enforces `ForceCommand`, public-key authentication, disabled
forwarding and PTY, and the existing allowed key. Check that the 0.3.0
dispatcher file and every fixed utility it calls are available on the target.
Do not expand SSH privileges or change credentials as part of this release.

Record the live image ID, container ID, Compose file, private `.env`, SSH
dispatcher, and SSH account configuration in a private backup directory with
restricted permissions. The following commands illustrate the capture; adjust
paths to the approved deployment and target. Do not place backups in Git.

```sh
umask 077
backup_dir=/private/backup/location
mkdir -p "$backup_dir"
docker compose --env-file /private/deployment/.env -f /private/deployment/compose.yaml \
  ps --format json > "$backup_dir/compose-ps.json"
docker inspect --format '{{.Image}}' "$(docker compose --env-file /private/deployment/.env \
  -f /private/deployment/compose.yaml ps -q inspector)" > "$backup_dir/inspector-image-id"
cp -p /private/deployment/compose.yaml /private/deployment/.env "$backup_dir/"
# Back up the installed ForceCommand and relevant sshd/authorized-keys configuration
# using the approved host administration channel into this private directory.
```

Ensure the old image remains locally available by its recorded ID. If it may
be pruned, give that **existing** image a local rollback tag or save it in the
private backup directory. Verify the saved image ID before replacement. Record
the current dispatcher SHA-256 and preserve its file mode and ownership.
Never depend on the mutable `0.2.0` tag without checking its image ID.

## 3. Upgrade order (explicit human authorization required)

1. Stage and validate the new dispatcher on the target. Confirm its SHA-256
   matches `host/sg-audit-dispatch.py` from the reviewed commit. Install it
   atomically with the original owner and executable mode, keeping a private
   copy of the old file. Do not change the ForceCommand path, account, key,
   forwarding, or PTY rules.
2. While **0.2.0 Inspector is still running**, invoke each legacy operation
   (`identity`, `uptime`, `listeners`, `services`) through the existing access
   path. `services` may report a diagnostic error if systemd is unavailable;
   an SSH authorization denial or transport failure is a stop condition.
   Check that an arbitrary SSH command is still denied with exit 126 through
   a controlled operator test. Do not advance on a compatibility failure.
3. Make the verified 0.3.0 image ID available on the deployment host and
   confirm its OCI version/revision labels. Confirm the single-host Compose
   file resolves to the approved image, secrets and network. Run the preflight
   again on that host against the staged dispatcher, **the exact Compose
   file used by the replacement command**, and recorded image ID.
4. Replace **only** the Inspector container using the approved Compose file:

   ```sh
   docker compose --env-file /private/deployment/.env \
     -f /private/deployment/compose.yaml up -d --no-deps --no-build inspector
   ```

   Confirm `docker inspect` reports the intended image ID, UID/GID 65533,
   read-only root, dropped capabilities, no privileged mode, no Docker socket,
   and no published port. Confirm Inspector starts and the Tunnel remains
   connected. Do not recreate or reconfigure `tunnel-client`.
5. Through the existing OpenAI Tunnel, perform read-only smoke calls:
   `inspector_status`, `list_hosts` (only `default`), `list_checks`,
   `inspect_server(identity)`, and `inspect(system.identity)` and
   `inspect(system.uptime)`. Check result status, host label, timestamp,
   non-root identity, and absence of diagnostic errors. Do not put host output
   in public CI or the PR. Test one unknown check and unknown host ID; both
   must be rejected without SSH execution. A local health check alone does
   not establish Tunnel access.

## 4. Immediate rollback conditions and order

Rollback immediately for incorrect image/revision, failed preflight, lost
Tunnel access, failed legacy diagnostics, denied intended checks, unexpected
host routing, missing secret mounts, SSH restriction drift, elevated container
privileges, a Docker socket mount, or exposure of sensitive output. Treat
ambiguous partial diagnostics as a failure until investigated.

With explicit operator authorization, first restore the **recorded 0.2.0
image ID** and original single-host Compose configuration, then recreate only
Inspector. Verify the old MCP tools through the Tunnel. Next restore the
backed-up 0.2.0 dispatcher atomically with its original owner and mode, and
verify the four legacy operations again. This order prevents a 0.3.0 Inspector
from sending new check IDs to an old dispatcher during rollback. Keep the
verified 0.3.0 artifact and evidence for investigation; do not retry blindly.

For the original deployment paths shown above, the container portion is:

```sh
old_image_id=$(cat "$backup_dir/inspector-image-id")
docker image inspect --format '{{.Id}}' "$old_image_id"
docker image tag "$old_image_id" infrastructure-inspector:0.2.0
cp -p "$backup_dir/compose.yaml" "$backup_dir/.env" /private/deployment/
docker compose --env-file /private/deployment/.env \
  -f /private/deployment/compose.yaml up -d --no-deps --no-build inspector
test "$(docker inspect --format '{{.Image}}' "$(docker compose \
  --env-file /private/deployment/.env -f /private/deployment/compose.yaml \
  ps -q inspector)")" = "$old_image_id"
```

Restore the dispatcher using the approved host administration channel from
the private backup. Verify its recorded checksum, ownership, and mode before
the four legacy smoke calls. Escalate if the rollback image or dispatcher
cannot be verified; do not substitute an unverified tag or file.

The current MCP transport has **no application-level OAuth**. Adding hosts,
multi-host SSH egress, Docker/Veeam or other sensitive privileged diagnostics,
or broader access requires a separate security review and explicit approval.
