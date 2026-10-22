import os
import subprocess
from pathlib import Path
from typing import Literal

from mcp.server import MCPServer
from mcp.server.transport_security import TransportSecuritySettings

mcp = MCPServer("ssh-inspector-dev", version="0.2.0")

SSH_KEY = "/run/secrets/sg-audit-ed25519"
SSH_HOST_KEYS = "/run/secrets/ssh-known-hosts"
SSH_TARGET = os.environ.get("INSPECTOR_SSH_TARGET", "")
HOST_LABEL = os.environ.get("INSPECTOR_HOST_LABEL", "unconfigured")

OPERATIONS = ("identity", "uptime", "listeners", "services")


@mcp.tool()
def inspector_status() -> dict:
    """Return inspector capabilities and configuration status."""
    return {
        "environment": "development",
        "mode": "ssh-allowlist",
        "ssh_key_present": Path(SSH_KEY).is_file(),
        "operations": list(OPERATIONS),
    }


@mcp.tool()
def inspect_server(
    operation: Literal["identity", "uptime", "listeners", "services"],
) -> dict:
    """Execute a predefined read-only SSH diagnostic on SERVER."""
    if operation not in OPERATIONS:
        raise ValueError("Unsupported diagnostic operation")

    if not SSH_TARGET:
        raise RuntimeError("INSPECTOR_SSH_TARGET is not configured")

    command = [
        "/usr/bin/ssh",
        "-F", "/dev/null",
        "-T",
        "-i", SSH_KEY,
        "-o", "IdentitiesOnly=yes",
        "-o", "IdentityAgent=none",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={SSH_HOST_KEYS}",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "UpdateHostKeys=no",
        "-o", "ConnectTimeout=5",
        "-o", "ConnectionAttempts=1",
        "-o", "ClearAllForwardings=yes",
        "-o", "HostKeyAlgorithms=ssh-ed25519",
        SSH_TARGET,
        operation,
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=15,
            env={
                "PATH": "/usr/bin:/bin",
                "HOME": "/home/inspector",
                "LANG": "C",
            },
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("SSH diagnostic timed out") from None

    if result.returncode != 0:
        raise RuntimeError(
            f"SSH diagnostic failed: exit={result.returncode}, "
            f"error={result.stderr[:1024]}"
        )

    return {
        "host": HOST_LABEL,
        "operation": operation,
        "exit_code": result.returncode,
        "output": result.stdout[:16384],
    }


if __name__ == "__main__":
    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=8000,
        stateless_http=True,
        json_response=True,
        max_request_body_size=65536,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=["inspector:8000"],
            allowed_origins=[],
        ),
    )
