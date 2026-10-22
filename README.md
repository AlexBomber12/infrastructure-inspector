# Infrastructure Inspector

Read-only infrastructure diagnostics through MCP and restricted SSH.

Infrastructure Inspector enables ChatGPT and other MCP clients to inspect Linux hosts without granting arbitrary shell access.

## Status

Version: 0.3.0 (development branch; production remains 0.2.0)

Production 0.2.0 provides MCP-to-SSH diagnostic transport. The checks below
describe development capability and require a separate, explicit deployment.

## Capabilities

MCP tools:

- `inspector_status`: reports available operations and configuration status.
- `inspect_server`: executes an explicitly allowed diagnostic operation.
- `list_checks()`: lists check IDs, descriptions, categories, privilege needs and limits.
- `inspect(check_id)`: runs one registered check.
- `inspect_batch(check_ids)`: runs one to five registered checks sequentially.

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

All checks are read-only and unprivileged. No check accepts parameters. The
legacy MCP tools and SSH operation strings remain available.

Each `inspect` result contains `host`, `check_id`, `collected_at` (UTC ISO
8601), `status` (`success`, `error`, or `incomplete`), `exit_code` (or null),
`output`, `truncated`, and `error` (or null). `incomplete` means output was
truncated. Output is limited to 16,384 bytes and error information to 1,024
characters; each SSH request has a 15-second deadline. A batch retains
individual results when another check fails and can take up to 75 seconds.

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

Copy `.env.example` to `.env` and configure deployment-specific values.

The example contains placeholders. Deployment requires a dedicated SSH account, authorized key, ForceCommand dispatcher, private key and trusted host key.

Never commit credentials, private keys, API keys or private infrastructure configuration.

Run the local validation gate using `bash scripts/ci.sh`. It validates Compose,
builds the Inspector image, runs the isolated unit tests, and checks the complete
Git history for secrets with a tested, version-pinned scanner.

## Tests

GitHub Actions validates Compose, builds the Inspector image and runs isolated unit tests without SSH credentials or network access.

Contributions follow the manual PR and review workflow in `AGENTS.md`. Production
Python coverage should be measured for both lines and branches as the test suite
grows toward 100%; this is not yet a CI threshold.

Unit tests do not replace integration testing of SSH restrictions on the target host.

To add a read-only check, add its fixed ID and metadata to
`inspector/catalog.py`, then separately authorize that exact ID with fixed
executable path and arguments in `host/sg-audit-dispatch.py`. Keep both maps
consistent, add tests for the command and rejection of parameters, and run
`bash scripts/ci.sh`. Deploying new diagnostic capability to production is
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
