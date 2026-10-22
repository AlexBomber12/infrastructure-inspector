# Infrastructure Inspector

Read-only infrastructure diagnostics through MCP and restricted SSH.

Infrastructure Inspector enables ChatGPT and other MCP clients to inspect Linux hosts without granting arbitrary shell access.

## Status

Version: 0.2.0

This version provides a working MCP-to-SSH diagnostic transport. It is not yet a complete infrastructure auditing system.

## Capabilities

MCP tools:

- `inspector_status`: reports available operations and configuration status.
- `inspect_server`: executes an explicitly allowed diagnostic operation.

Supported operations:

| Operation | Linux command |
| --- | --- |
| identity | id |
| uptime | uptime |
| listeners | ss -H -lnt |
| services | systemctl list-units --type=service --state=running --no-pager --plain --no-legend |

Arbitrary shell execution, file modification, package installation, service management and reboots are not supported.

## Architecture

ChatGPT -> OpenAI Tunnel -> MCP Inspector -> SSH -> ForceCommand dispatcher

The server-side dispatcher independently enforces an operation allowlist.

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

Validate Docker Compose using:

`docker compose --env-file .env.example config --quiet`

## Tests

GitHub Actions validates Compose, builds the Inspector image and runs isolated unit tests without SSH credentials or network access.

Unit tests do not replace integration testing of SSH restrictions on the target host.

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
