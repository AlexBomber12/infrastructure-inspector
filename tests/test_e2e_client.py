"""Full MCP -> Inspector -> OpenSSH -> ForceCommand checks in isolated Docker."""
import asyncio
import json
import os
import subprocess

import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

URL = "http://inspector:8000/mcp"
SSH = [
    "/usr/bin/ssh", "-F", "/dev/null", "-T", "-o", "BatchMode=yes",
    "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=5",
    "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "IdentitiesOnly=yes",
    "-o", "IdentityAgent=none", "-o", "GlobalKnownHostsFile=/dev/null",
]


def payload(result):
    assert not result.is_error, result
    if result.structured_content is not None:
        return result.structured_content.get("result", result.structured_content)
    return json.loads(result.content[0].text)


async def call(name, args=None):
    async with streamable_http_client(URL) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await session.call_tool(name, args or {})


def ssh(command, *, key="/run/fixture/key", known_hosts="/run/fixture/known_hosts"):
    return subprocess.run(
        SSH + ["-i", key, "-o", f"UserKnownHostsFile={known_hosts}",
               "audit@sshd", command], capture_output=True, timeout=15,
    )


def test_legacy_operation():
    result = payload(asyncio.run(call("inspect_server", {"operation": "identity"})))
    assert result["host"] == "e2e-host"
    assert result["operation"] == "identity"
    assert result["exit_code"] == 0
    assert b"uid=" in result["output"].encode()


def test_new_catalog_check():
    result = payload(asyncio.run(call("inspect", {"check_id": "system.os"})))
    assert result["host"] == "e2e-host"
    assert result["check_id"] == "system.os"
    assert result["status"] == "success"
    assert result["exit_code"] == 0
    assert result["truncated"] is False
    assert "ID=" in result["output"]
    assert result["error"] is None
    assert result["collected_at"].endswith("+00:00")


def test_batch_multiple_checks():
    result = payload(asyncio.run(call("inspect_batch", {"check_ids": ["system.identity", "system.kernel"]})))
    assert [item["check_id"] for item in result] == ["system.identity", "system.kernel"]
    assert all(item["host"] == "e2e-host" and item["status"] == "success" for item in result)
    assert "uid=" in result[0]["output"]
    assert "Linux" in result[1]["output"]


def test_unsupported_check_rejected():
    result = asyncio.run(call("inspect", {"check_id": "system.os; id"}))
    assert result.is_error


def test_force_command_rejects_arbitrary_ssh():
    result = ssh("/usr/bin/id")
    assert result.returncode == 126
    assert b"DENIED" in result.stderr


def test_wrong_key_rejected():
    result = ssh("identity", key="/run/fixture/wrong_key")
    assert result.returncode == 255
    assert b"Permission denied" in result.stderr


def test_host_key_mismatch_rejected():
    result = ssh("identity", known_hosts="/run/fixture/wrong_known_hosts")
    assert result.returncode == 255
    assert b"Host key verification failed" in result.stderr


def test_shell_injection_rejected():
    result = ssh("identity; id")
    assert result.returncode == 126
    assert b"DENIED" in result.stderr


def test_unavailable_ssh_server():
    result = payload(asyncio.run(asyncio.wait_for(
        call("inspect", {"check_id": "system.os"}), timeout=20,
    )))
    assert result["status"] == "error"
    assert result["exit_code"] != 0
    assert result["error"]
    assert "PRIVATE KEY" not in json.dumps(result)
