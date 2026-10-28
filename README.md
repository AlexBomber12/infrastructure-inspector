# Infrastructure Inspector

Read-only infrastructure diagnostics through MCP and restricted SSH.

Infrastructure Inspector enables ChatGPT and other MCP clients to inspect Linux hosts without granting arbitrary shell access.

## Status

Version: 0.3.0. The operator reports that production runs the 0.3.0 image;
automated tests do not attest the live deployment.

The single-host 0.3.0 release image is `infrastructure-inspector:0.3.0`.
For the single-host deployment procedure, use the [release preflight and rollback
runbook](docs/release-0.3.0-single-host.md). This repository change does not
deploy or replace the running service.

The checks below describe the 0.3.0 application contract. CI tests them against
disposable hosts; live production behavior requires operator verification.

## Capabilities

MCP tools:

- `inspector_status`: reports available operations and configuration status.
- `inspect_server`: executes an explicitly allowed diagnostic operation.
- `list_checks()`: lists check IDs, descriptions, categories, privilege needs and limits.
- `list_hosts()`: lists configured host IDs and safe display labels.
- `inspect(check_id, host_id=None)`: runs one registered check on the selected host.
- `inspect_batch(check_ids, host_id=None)`: runs one to five registered checks on one selected host.

Supported operations:

| Legacy operation | Check ID | Fixed Linux command |
| --- | --- | --- |
| identity | system.identity | /usr/bin/id |
| uptime | system.uptime | /usr/bin/uptime |
| listeners | network.listeners | /usr/bin/ss -H -lnt |
| services | system.services | /usr/bin/systemctl list-units --type=service --state=running --no-pager --plain --no-legend |
| — | system.os | /usr/bin/cat /etc/os-release |
| — | system.kernel | /usr/bin/uname -srmo |
| — | system.cpu | /usr/bin/lscpu |
| — | system.memory | /usr/bin/free -b |
| — | system.block_devices | /usr/bin/lsblk --json --bytes -o NAME,KNAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS,MODEL,TRAN |
| — | system.filesystems | /usr/bin/df -P -B1 -T |
| — | system.mounts | /usr/bin/findmnt --json -o TARGET,SOURCE,FSTYPE |
| — | system.processes | /usr/bin/ps -eo pid,ppid,user,stat,comm --sort=pid |
| — | network.interfaces | /usr/sbin/ip -j address show |
| — | network.routes_ipv4 | /usr/sbin/ip -j -4 route show |
| — | network.routes_ipv6 | /usr/sbin/ip -j -6 route show |
| — | gpu.nvidia.status | /usr/bin/nvidia-smi --query-gpu=index,name,driver_version,pstate,temperature.gpu,utilization.gpu,memory.total,memory.used,power.draw --format=csv |
| — | gpu.nvidia.compute_processes | /usr/bin/nvidia-smi --query-compute-apps=pid,used_gpu_memory --format=csv |

All checks are read-only and unprivileged. No check accepts parameters. The
legacy MCP tools and SSH operation strings remain available.

The seven inventory checks above report block device names, sizes, filesystem
types, mountpoints, models and transport; filesystem byte capacity and usage;
mount targets and sources; process IDs, parent IDs, users, states and names;
interface addresses; and IPv4 and IPv6 routes. They require only the dedicated
unprivileged SSH account. `system.processes` uses the process name (`comm`),
not command-line arguments or environment variables. No check requests disk
serial numbers, SSH keys, credentials or arbitrary file contents.

An empty JSON device or route list can be a complete, successful result.
`error` indicates a command or transport failure; an unavailable utility may
produce this status with a nonzero exit code. `incomplete` and `truncated: true`
mean the bounded stdout is partial and must not be treated as a complete
inventory, particularly for process and mount tables. The fixed 16,384-byte
limit also applies to device and network output. Exhaustive inventory on a
larger host would need a separately designed pagination interface. These
checks cover selected Linux diagnostics, not a complete infrastructure
inventory.

Each `inspect` result contains `host`, `host_id`, `check_id`, `collected_at` (UTC ISO
8601), `status` (`success`, `error`, or `incomplete`), `exit_code` (or null),
`output`, `truncated`, `stderr_truncated`, and `error` (or null).
`incomplete` means diagnostic stdout was truncated; `stderr_truncated`
indicates separately that some error or warning text was dropped. Output is
limited to 16,384 bytes and error information to 1,024
characters; each SSH request has a 15-second deadline. A batch retains
individual results when another check fails and can take up to 75 seconds.

The two NVIDIA checks use category `gpu` and require a working
`/usr/bin/nvidia-smi` accessible to the unprivileged audit account on the target.
They return raw CSV with its headers and units. Status fields report GPU index,
name, driver version, performance state, temperature, utilization, total and
used GPU memory, and power draw. Unsupported measurements such as `[N/A]` or
`N/A` remain unchanged and are successful when the command succeeds. They are
never converted to zero. DGX Spark uses shared system memory; `system.memory`
reports OS-level memory, not memory allocated exclusively to the GPU.

The compute query returns process IDs and used GPU memory. Header-only output
is a valid successful empty result. This query covers compute processes, not
every graphics process. These fields contain no GPU identifier and cannot
establish per-GPU attribution on multi-GPU systems.

The existing limits apply: the dispatcher allows 10 seconds, 16,384 stdout
bytes and 1,024 stderr bytes; Inspector allows 15 seconds per SSH request and
the output/error limits described above. Missing executables, permission or
driver failures, nonzero exits and timeouts remain errors; truncated stdout
remains incomplete. A failed GPU check does not discard other batch results.

Deployment requires separately reviewed Inspector and dispatcher updates on
each intended target. A catalog update alone does not authorize target-side
commands. NVIDIA runs only on the inspected host; Inspector needs no NVIDIA
packages, GPU access, device mounts or Docker socket. Disposable synthetic tests
verify the protocol behavior, not physical GPU compatibility, restricted audit
account access on real GPU hosts, or production rollout. No production
onboarding or deployment is part of this change.

Arbitrary shell execution, file modification, package installation, service management and reboots are not supported.

## Architecture

ChatGPT -> OpenAI Tunnel -> MCP Inspector -> SSH -> ForceCommand dispatcher

The server-side dispatcher independently enforces an operation allowlist.
It must do so even when the MCP catalog has already validated an ID: SSH
requests can reach the dispatcher independently, and the two components may
be deployed at different times.

The SSH private key remains on the deployment host and is mounted read-only into the Inspector container.

## Security

- Dedicated unprivileged SSH account
- Public-key authentication
- Server-side ForceCommand
- Disabled SSH forwarding and interactive terminals
- Strict SSH host-key verification
- Non-root Docker containers
- Read-only container filesystems
- Dropped Linux capabilities
- Execution time and resource limits
- No published Docker ports
- No Docker socket mounted into Inspector
- Fixed diagnostic operations

The internal Docker network can reach its bridge gateway. SSH access through that gateway is intentional and must be restricted by host SSH configuration.

These controls reduce risk but do not guarantee complete isolation.

## Authentication

The current MCP server does not implement caller authentication.

Deploy only through an access-controlled transport.

Do not expose the MCP endpoint publicly without appropriate authentication and authorization.

Do not extend the current authentication model to privileged operations or sensitive data access.

## Configuration

For production, copy `.env.example` to an operator-owned `.env` outside Git and
configure deployment-specific values, including the full verified
`INSPECTOR_IMAGE_ID`. Pass it with Compose `--env-file`; this file supplies
Compose interpolation. The single-host Compose file has no build path.

The example contains placeholders. Deployment requires a dedicated SSH account, authorized key, ForceCommand dispatcher, private key and trusted host key.

### Multiple hosts (opt in)

The existing `compose.yaml` and `.env.example` remain the supported single-host
deployment. In that mode, the one host has public ID `default`; calls that omit
`host_id` use it. For a separately reviewed multi-host deployment, use
`compose.multi.yaml` and `.env.multi.example` as the starting points. The
multi-host mode is selected by `INSPECTOR_HOST_MODE=multi`; a missing or invalid
registry fails startup and never falls back to the legacy SSH target. Do not
combine the two Compose files.
The legacy `INSPECTOR_SSH_TARGET` accepts fixed `user@hostname`, bracketed
IPv6, and OpenSSH `ssh://[user@]hostname[:port]` destinations so existing
non-default-port deployments continue to work. URI ports must be 1–65535.
Native unbracketed IPv6 and constrained `%interface` scope names are accepted.
Bracketed IPv6 inside an `ssh://` URI is rejected because the deployed
OpenSSH client does not parse that form.
The `ssh://` scheme must be lowercase. These values remain operator-set
environment configuration, never MCP input.

The operator-owned JSON file is mounted read-only at
`/run/secrets/host-registry.json`. See `examples/host-registry.json` for a
synthetic example. Its exact schema is `{"default_host":"id","hosts":[...]}`;
each host entry contains exactly `id`, `label`, and `target`. IDs use 1–32
lowercase ASCII letters, digits, underscores or hyphens and start with a
letter. Labels use 1–64 safe printable characters. Targets have the fixed
`user@hostname` or `user@[IPv6-address]` form, with no SSH options, port,
whitespace or path syntax. Bracketed IPv6 addresses are validated and passed
to OpenSSH without the brackets.
There must be 1–8 hosts, unique IDs, and a default ID present in the list.
The file is capped at 8 KiB; duplicate JSON fields and unknown fields fail.

For host ID `example-a`, mount a dedicated private key at
`/run/secrets/inspector-hosts/example-a/identity` and its trusted host-key file
at `/run/secrets/inspector-hosts/example-a/known_hosts`. The names are derived
from the validated ID; callers cannot provide credential paths or SSH targets.
Each host uses its own key and `known_hosts`. The registry and credential tree
must be mounted read-only and readable by container UID 65533. Keep them out
of the public repository. The Inspector still uses strict host-key checking,
disables agent and forwarding, and relies on each target's independent
ForceCommand allowlist. The server-side dispatcher must be installed and
configured separately on every additional Linux host.

The multi-host Compose file keeps `mcp-private` internal and attaches only the
Inspector to a separate `ssh-egress` bridge. The reviewed migration and
network policy procedure is in [docs/multi-host-migration.md](docs/multi-host-migration.md).
The tunnel client is not attached to `ssh-egress`.

To add a host, provision its dedicated unprivileged audit account, ForceCommand
dispatcher, authorized client key, and verified SSH host key; add the matching
private key and `known_hosts` under its ID directory; then add its registry
entry and restart the Inspector after an operator security review. Changing the
default host changes where old `inspect`, `inspect_batch`, and `inspect_server`
calls run, so preserve the existing default during migration unless callers
have been reviewed. A requested host ID is only a lookup into the trusted
registry and is never passed to SSH as a destination.

The MCP transport has no application-level OAuth. This repository change does
not authorize access to additional production hosts or a production rollout.
Actual access expansion needs a separate security review and explicit operator
approval. The disposable tests do not verify production authentication, network
policy, target configuration, or the OpenAI Tunnel; a production smoke test
remains a separately authorized activity.

Never commit credentials, private keys, API keys or private infrastructure configuration.

Run the complete local validation gate with `bash scripts/ci.sh`. WSL development
requires a working Docker Engine with Compose, `ssh-keygen`, and network access to
pull the pinned base images and Python packages. The gate validates Compose,
builds the Inspector and test images, runs unit and MCP transport tests, runs a
disposable SSH stack, and checks Git history and pending files with pinned
Gitleaks. No production credentials or hosts are needed.

## Tests

GitHub Actions has separate **Unit & integration**, **E2E SSH**, and **Secret
scan** jobs. `scripts/ci.sh` invokes the same test scripts locally. A missing
Docker daemon, failed startup, skipped mandatory test, or missing coverage data
fails the gate.

The unit layer executes the production Python modules and covers normal and error
paths, subprocess limits, and dispatcher authorization. The protocol layer uses
the MCP SDK client over real Streamable HTTP against a disposable Inspector with
a controlled SSH execution fixture. Coverage.py measures all first-party
production Python files in `inspector/`, `host/`, and the release preflight in
`scripts/`, including branch arcs;
pytest-cov prints missing lines and branches and fails below 100%. Test files
are outside the coverage source paths.

The E2E layer starts actual Inspector, two independent OpenSSH targets, and MCP client containers on an
internal Docker network with no published ports. It generates temporary SSH
keys and pinned `known_hosts`, and uses this repository's real ForceCommand
dispatcher. It tests legacy and catalog operations, batching, unauthorized
commands, bad authentication, host-key mismatch, injection, and an unavailable
SSH server. Inspector runs as a non-root user without capabilities, a writable
root filesystem, or a Docker socket. Fixture credentials are deleted afterward.

These tests establish the behavior of the disposable stack. They do not verify
the OpenAI Tunnel or a production host's SSH configuration, installed commands,
network policy, or credentials. A production smoke test, if requested, requires
explicit authorization, uses only read-only operations, and runs separately
from normal CI. It must not upload credentials or host output to public reports.

Unit tests do not replace integration testing of SSH restrictions on the target host.

To add a read-only check, add its fixed ID and metadata to
`inspector/catalog.py`, then separately authorize that exact ID with fixed
executable path and arguments in `host/sg-audit-dispatch.py`. Keep both maps
consistent, add tests for the command and rejection of parameters, and run
`bash scripts/ci.sh`. Add unit tests for the new paths, protocol coverage for
the published contract, and a disposable SSH E2E assertion. Deploying new diagnostic capability to production is
a separate decision and is not part of adding it to this repository.

## Roadmap

- Hardware and operating system inventory
- Network and security diagnostics
- Docker inventory
- System and application logs
- SMART, RAID and storage diagnostics
- Veeam backup monitoring
- ASUSWRT-Merlin diagnostics
- Multi-host inventory
- Vulnerability assessment and investigations

The development phase remains strictly read-only.

## License

No license has been granted yet. Public repository visibility does not itself grant permission to reuse or redistribute the code.
