# Linux multi-host migration review

This procedure is for the existing `infrastructure-inspector` Compose project.
It does not authorize a production migration. Keep the existing Tunnel container
and its two networks. Only Inspector is recreated. Do not use `compose down`,
`--force-recreate` for the Tunnel, or a Compose file merge.

## Architecture and security decision

The existing bounded registry selects a trusted `host_id`. Keep `default` as
the existing SERVER, with its current diagnostic SSH destination and credentials.
Use a second ID for AI-Server. Both targets retain their own unprivileged audit
account, pinned host key, private client key, and server-side ForceCommand. No
new MCP endpoint, server, key, or dispatcher is created by this migration.

`compose.multi.yaml` uses the same project and Tunnel definition as
`compose.yaml`. Inspector uses the operator-verified local image ID with
`pull_policy: never` and has no build path. It alone joins `ssh-egress`. Static
container IPv4 addresses and a reserved private MAC let a dedicated host policy match Inspector without
changing Docker's chains or the Tunnel. The egress bridge has a stable explicit
interface name and disables inter-container communication and IPv6. The
`mcp-private` bridge remains internal. Inspector has no automatic restart in
multi-host mode, so it cannot start by itself after a Docker restart before
the operator verifies the policy.

The `inspector_multi` nftables table is independent of Docker's iptables-nft
tables. Inspector alone uses a loopback DNS sink; the table's host `output`
hook blocks UDP and TCP port 53 to that sink, including Docker's upstream
forwarding outside the bridge hooks. The Tunnel keeps its internal service
discovery. The table's `input` hook permits only the private bridge gateway on TCP 22 and
rejects other host-local destinations from Inspector's private MAC. It
rejects all host-local traffic from the dedicated egress bridge. Its `forward`
hook rejects private-network egress and permits egress-network SSH only to the
listed external IPv4 endpoints. Both hooks reject IPv6 from the egress bridge
and Inspector's private MAC.
Established responses are allowed. The source match for the private bridge
uses `br-*` plus Inspector's reserved MAC, so a recreated Docker bridge keeps
matching; the Docker daemon must reject overlapping bridge subnets. Every
future host needs a corresponding privately configured allow destination and
packet tests before Inspector is started.

## Prerequisites and preflight

1. Confirm the host uses Linux, Docker's iptables backend with nf_tables
   compatibility, `nft`, and `net.bridge.bridge-nf-call-iptables=1`. Inspect
   `ip -4 route`, `ip -6 route`, `docker network inspect`, VPN routes, remote
   routes, and the intended private and egress pools. Reject any overlap. Do
   not change Docker's firewall backend, Docker chains, UFW, or unrelated
   networks. Verify the selected static addresses are unused and are neither
   gateway nor network/broadcast addresses.
2. Keep the operator env file, registry, and credential tree outside Git.
   Set `INSPECTOR_IMAGE_ID` to the full, independently verified local image ID.
   Reserve a unique locally administered private MAC in the operator env file.
   The registry must have `default_host: "default"`; the `default` target must
   be the existing gateway SSH destination. Use literal IPv4 addresses for
   external targets so the firewall and SSH destination cannot diverge through
   DNS. Match every external target to the policy allow list. For each ID,
   provide `identity` and `known_hosts` under the mounted credential tree.
   Reuse the existing SERVER key and pinned host key by installing protected
   copies in `default/`; use the already prepared independent AI-Server files
   in its own ID directory. Do not generate replacement keys or edit either
   host's `authorized_keys`. Private keys should be owned by UID 65533 with
   mode 0600; registry and host-key files must be readable by UID 65533.
3. Immediately before migration, capture a **fresh** rollback snapshot from
   the currently running single-host Inspector and Tunnel container IDs:

   ```sh
   bash scripts/release_snapshot.sh capture "$SNAPSHOT" "$OLD_ENV" "$OLD_INSPECTOR_ID" "$TUNNEL_ID"
   bash scripts/release_snapshot.sh verify-current "$SNAPSHOT"
   ```

   This guards against an older snapshot referencing a replaced Inspector.
   Record the Tunnel ID and its Compose config hash separately. The snapshot
   copies the original env and Compose files into a root-protected directory.
4. Run `scripts/release_preflight.py` with the intended `--compose-file`,
   `--env-file`, `--project-name`, `--revision`, `--deployment-revision`,
   `--image-id`, and `--snapshot`. It checks the effective Compose contract,
   immutable image and source revision, Inspector DNS sink, current snapshot, Tunnel hash, registry
   schema and default ID, and actual mounted credential readability using
   constrained, named Docker probes. No credential contents are printed. A failed
   probe stops migration. If a probe times out and targeted container cleanup
   cannot be confirmed, inspect the reported disposable container name before
   proceeding; no broad Docker cleanup is performed.

## Network policy and controlled start

Stop only the old Inspector after the fresh snapshot. Render the proposed
policy using the reserved private address and MAC, private gateway, reserved egress
address, dedicated bridge name, and **each** external target IPv4 address:

```sh
bash scripts/multi_network_policy.sh render "$PRIVATE_IP" "$PRIVATE_MAC" "$PRIVATE_GATEWAY" "$EGRESS_IP" "$EGRESS_BRIDGE" "$AI_IP" > "$PRIVATE_POLICY"
```

Keep this file operator-owned outside Git. Review it against the registry and
actual routes. Install it before starting or attaching the new Inspector to
`ssh-egress`:

```sh
sudo bash scripts/multi_network_policy.sh install "$PRIVATE_IP" "$PRIVATE_MAC" "$PRIVATE_GATEWAY" "$EGRESS_IP" "$EGRESS_BRIDGE" "$AI_IP"
```

The install validates then atomically replaces only `inet inspector_multi`.
For the systemd deployment, use the reviewed units in `deploy/systemd/` and
`scripts/multi_host_service.sh`. The policy oneshot installs and verifies the
reviewed table. The Inspector unit requires the policy, binds to Docker, and verifies
the table again immediately before `docker compose up --no-deps --exit-code-from inspector
inspector`, and has no automatic restart. It does **not** alter `docker.service`
or its dependencies: unrelated containers, including Tunnel, remain free to
start. The service's `ExecStop` and `ExecStopPost` call the same bounded cleanup.
`ExecStopPost` runs even when policy verification or startup fails. Cleanup
identifies a multi-host container by the exact Compose project, service,
configuration hash, immutable image ID, source file, mode, restart policy,
network attachments, addresses, and reserved MAC. A legacy single-host
Inspector has no multi-host mode marker and is left running. An unexpected
multi-host identity or Docker error makes cleanup fail visibly. It never stops
Tunnel and never uses project-wide Compose stop/down or removal.

The policy unit intentionally has no automatic removal action. Keep it installed
after confirmed stop until an operator reviews removal. If Docker is unavailable
or stopping/state verification fails, treat shutdown as unresolved and retain
the table. A Docker daemon restart with `live-restore=false` stops Inspector;
its Compose `restart: "no"` and the unit's `Restart=no` prevent an unattended
restart. `BindsTo=docker.service` stops the unit when Docker is stopped by
systemd and does not start Inspector when Docker later returns. The Tunnel's
`unless-stopped` remains independent. After Docker returns, an operator must verify policy and packet behavior before restarting
Inspector. An arbitrary nftables flush *while Inspector is already running* is
a separate exposure mode. The synchronous start and stop ordering cannot
prevent packets in that interval; no asynchronous monitor could guarantee zero
exposure after such a flush. Stop Inspector before firewall maintenance and
repeat verification before restart. If this operating constraint cannot be
met, do not migrate.

### Reviewed installation after separate approval

The two production unit files currently staged outside Git are uninstalled.
Do not replace or enable them as part of this PR. After approval, compare those
files with `deploy/systemd/infrastructure-inspector-policy.service` and
`deploy/systemd/infrastructure-inspector-multi.service`. Review and install a
root-owned, mode 0600 `/etc/infrastructure-inspector/multi-host-unit.conf` from
the example, replacing every example address and path with the private values.
The host needs `bash`, `jq`, GNU `timeout`, Docker Compose v2, `nft`, and
`systemd-analyze`. Use the exact absolute canonical path to the reviewed
`compose.multi.yaml`, the private Compose env file, the existing Compose project, and every external
IPv4 allow destination. Install the reviewed checkout at
`/opt/infrastructure-inspector` or adjust both unit `Exec*` paths during
review. Run `systemd-analyze verify` on the **proposed** units and compare the
rendered policy against registry targets and host routes. Preserve copies of
the staged files for rollback; replace them only after the operator approves
the final unit and config diff. Then `systemctl daemon-reload`, enable the
policy unit, and start it. Confirm `verify` and packet tests before stopping
the old Inspector. Keep the fresh snapshot and run the full release preflight
while that old Inspector is still running. Only after preflight passes, stop
**only** the old Inspector, start `infrastructure-inspector-multi.service`,
and verify its status, runtime identity, MCP diagnostics, and the unchanged
Tunnel ID/config hash. Do not enable the multi-host unit at boot until the
operator has reviewed and accepted the running candidate. A failed unit start
must be investigated; its post-stop cleanup is not a successful migration.

The unit's foreground Compose command starts only Inspector, with the exact
reviewed Compose file, env file, project, immutable image, and `--no-deps`.
Do not issue a separate detached `compose up` during the managed lifecycle.

Verify the new Inspector's image ID, UID/GID, mounts, exact two network
attachments, static addresses, IPv6-disabled networks, no published ports,
routes, and running state. Confirm the Tunnel ID and config hash remain equal
to the snapshot. Run allowed read-only checks for both IDs, legacy
`inspect_server`, a batch, and rejection cases. Use disposable probes to show
packets to unapproved remote endpoints, host-local addresses and lateral
containers are rejected. Verify Inspector cannot resolve external DNS names
through Docker's embedded resolver while Tunnel-to-Inspector service discovery
still works. Verify the already configured `authorized_keys`
source restriction still sees the expected SERVER source after Docker NAT;
the repository's synthetic NAT test does not establish this production fact.

## Rollback

Stop the multi-host unit, run the cleanup helper again with the reviewed unit
configuration, and confirm no multi-host Inspector is running. If Docker cannot
confirm this, retain the nftables policy and do not claim rollback complete.
Verify the snapshot and restore only Inspector from the captured effective configuration and immutable old image:

```sh
bash scripts/release_snapshot.sh verify "$SNAPSHOT"
docker compose -f "$SNAPSHOT/effective.json" -f "$SNAPSHOT/rollback-image.yaml" -p "$PROJECT" up -d --no-deps --no-build --pull never inspector
```

Confirm the old image, environment, private-only network attachment, working
legacy diagnostic, and original Tunnel ID and hash. Remove only the newly
created `${PROJECT}_ssh-egress` network after confirming no container uses it.
Disable the new policy boot unit. Remove only `inet inspector_multi`
after Docker confirms the candidate is stopped and the old Inspector is
restored. Keep the snapshot and credentials protected for incident review. Never prune unrelated networks or images as part of rollback.

## Evidence and remaining production checks

`bash scripts/ci.sh` exercises the same unit, integration, and E2E paths as CI.
The E2E path uses two independently keyed disposable OpenSSH targets and the
real dispatcher. A separate privileged test container has no network
attachment and creates its own network namespaces; it checks allowed and
rejected packets, host-local processing, route changes, bridge recreation,
IPv6, DNS sink packet rejection, synthetic masquerading, and policy removal.
A separate Docker-backed test exercises embedded DNS with a synthetic peer:
peer discovery succeeds and external resolution fails. The disposable lifecycle
test validates the unit dependency graph with `systemd-analyze`, kills a
foreground Compose process, and exercises the exact stop helper against Docker.
It does not run a real systemd PID 1. These tests do not prove
the real host's nft persistence, Docker daemon restart behavior, actual route
table, Docker NAT source, or Tunnel continuity during migration. Those require
an operator-controlled staging run and production preflight before rollout.

The policy depends on Inspector retaining its reserved private MAC and exactly
the reviewed two attachments; verify both after recreation. The Docker networks
also keep IPv6 disabled. A firewall flush while Inspector is running could
expose it until the policy is restored; the service lifecycle covers ordinary start/stop failures, not
this arbitrary deletion. A real host staging run must prove systemd and Docker
restart behavior before production activation. Do not claim complete
isolation from repository tests alone.
