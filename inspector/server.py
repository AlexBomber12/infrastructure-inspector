import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from mcp.server import MCPServer
from mcp.server.transport_security import TransportSecuritySettings

from bounded import run_bounded
from catalog import CHECKS, LEGACY_OPERATIONS

mcp = MCPServer("ssh-inspector-dev", version="0.3.0")

SSH_KEY = "/run/secrets/sg-audit-ed25519"
SSH_HOST_KEYS = "/run/secrets/ssh-known-hosts"
SSH_TARGET = os.environ.get("INSPECTOR_SSH_TARGET", "")
HOST_LABEL = os.environ.get("INSPECTOR_HOST_LABEL", "unconfigured")

OPERATIONS = tuple(LEGACY_OPERATIONS)
MAX_BATCH = 5
ERROR_LIMIT = 1024


def _safe_error(value):
    value = re.sub(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*\x07)", "", value)
    return "".join(c if c.isprintable() or c in "\n\t" else "?" for c in value)[:ERROR_LIMIT]


def _ssh_command(operation):
    return [
        "/usr/bin/ssh", "-F", "/dev/null", "-T", "-i", SSH_KEY,
        "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
        "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={SSH_HOST_KEYS}",
        "-o", "GlobalKnownHostsFile=/dev/null", "-o", "UpdateHostKeys=no",
        "-o", "ConnectTimeout=5", "-o", "ConnectionAttempts=1",
        "-o", "ClearAllForwardings=yes", "-o", "HostKeyAlgorithms=ssh-ed25519",
        SSH_TARGET, operation,
    ]


def _run_check(check_id, operation):
    check = CHECKS[check_id]
    result = {
        "host": HOST_LABEL,
        "check_id": check_id,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "status": "error",
        "exit_code": None,
        "output": "",
        "truncated": False,
        "error": None,
    }
    if not SSH_TARGET:
        result["error"] = "INSPECTOR_SSH_TARGET is not configured"
        return result
    try:
        captured = run_bounded(
            _ssh_command(operation), timeout=check.timeout_seconds,
            stdout_limit=check.max_output_bytes, stderr_limit=ERROR_LIMIT,
            env={"PATH": "/usr/bin:/bin", "HOME": "/home/inspector", "LANG": "C"},
        )
    except subprocess.TimeoutExpired:
        result["error"] = "SSH diagnostic timed out"
        return result
    except OSError:
        result["error"] = "SSH diagnostic could not start"
        return result
    result["exit_code"] = captured.returncode
    result["output"] = captured.stdout.decode("utf-8", errors="replace")
    error = _safe_error(captured.stderr.decode("utf-8", errors="replace"))
    result["truncated"] = captured.truncated or (
        captured.returncode == 125
        and error.startswith("ERROR: diagnostic output truncated")
    )
    if result["truncated"]:
        result["status"] = "incomplete"
        result["error"] = error or "Diagnostic output was truncated"
    elif captured.returncode != 0:
        result["error"] = error or "SSH diagnostic failed"
    else:
        result["status"] = "success"
    return result


@mcp.tool()
def list_checks() -> list[dict]:
    """List supported read-only checks and their execution limits."""
    return [
        {"check_id": check_id, "description": check.description,
         "category": check.category, "requires_elevation": check.requires_elevation,
         "timeout_seconds": check.timeout_seconds,
         "max_output_bytes": check.max_output_bytes}
        for check_id, check in CHECKS.items()
    ]


@mcp.tool()
def inspect(check_id: str) -> dict:
    """Run exactly one registered read-only diagnostic check."""
    if not isinstance(check_id, str) or check_id not in CHECKS:
        raise ValueError("Unsupported diagnostic check")
    return _run_check(check_id, check_id)


@mcp.tool()
def inspect_batch(check_ids: list[str]) -> list[dict]:
    """Run up to five registered checks sequentially, preserving each result."""
    if not isinstance(check_ids, list) or not 1 <= len(check_ids) <= MAX_BATCH:
        raise ValueError("Expected one to five diagnostic checks")
    if any(not isinstance(check_id, str) or check_id not in CHECKS for check_id in check_ids):
        raise ValueError("Unsupported diagnostic check")
    return [_run_check(check_id, check_id) for check_id in check_ids]


@mcp.tool()
def inspector_status() -> dict:
    """Return legacy inspector capabilities and configuration status."""
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
    """Execute a legacy read-only SSH diagnostic on SERVER."""
    if not isinstance(operation, str) or operation not in LEGACY_OPERATIONS:
        raise ValueError("Unsupported diagnostic operation")
    result = _run_check(LEGACY_OPERATIONS[operation], operation)
    if result["status"] != "success":
        raise RuntimeError(result["error"] or "SSH diagnostic failed")
    return {
        "host": result["host"], "operation": operation,
        "exit_code": result["exit_code"], "output": result["output"],
    }


if __name__ == "__main__":
    mcp.run(
        transport="streamable-http", host="0.0.0.0", port=8000,
        stateless_http=True, json_response=True, max_request_body_size=65536,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=["inspector:8000"], allowed_origins=[],
        ),
    )
