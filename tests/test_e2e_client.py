"""Full MCP -> Inspector -> OpenSSH -> ForceCommand checks in isolated Docker."""
import asyncio
import json
import os
import subprocess
from datetime import datetime

import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

URL = "http://inspector:8000/mcp"
ORIGINAL_CHECKS = (
    "system.identity", "system.uptime", "network.listeners", "system.services",
    "system.os", "system.kernel", "system.cpu", "system.memory",
)
INVENTORY_CHECKS = (
    "system.block_devices", "system.filesystems", "system.mounts",
    "system.processes", "network.interfaces", "network.routes_ipv4",
    "network.routes_ipv6",
)
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


def test_all_legacy_ssh_strings_reach_new_dispatcher():
    for operation in ("identity", "uptime", "listeners", "services"):
        result = ssh(operation)
        assert result.returncode != 126, (operation, result.stderr)
        assert b"DENIED" not in result.stderr


def test_new_catalog_check():
    result = payload(asyncio.run(call("inspect", {"check_id": "system.os"})))
    assert result["host"] == "e2e-host"
    assert result["host_id"] == "a"
    assert result["check_id"] == "system.os"
    assert result["status"] == "success"
    assert result["exit_code"] == 0
    assert result["truncated"] is False
    assert "ID=" in result["output"]
    assert result["error"] is None
    assert result["collected_at"].endswith("+00:00")


def assert_result_schema(result, check_id):
    assert set(result) == {
        "host", "host_id", "check_id", "collected_at", "status", "exit_code",
        "output", "truncated", "stderr_truncated", "error",
    }
    assert result["host"] == "e2e-host"
    assert result["host_id"] == "a"
    assert result["check_id"] == check_id
    assert datetime.fromisoformat(result["collected_at"]).utcoffset().total_seconds() == 0
    assert result["status"] in {"success", "error", "incomplete"}
    assert isinstance(result["output"], str)
    assert len(result["output"].encode()) <= 16384
    assert isinstance(result["truncated"], bool)
    assert isinstance(result["stderr_truncated"], bool)
    assert result["error"] is None or len(result["error"]) <= 1024


def test_catalog_discovery_and_original_checks():
    checks = payload(asyncio.run(call("list_checks")))
    assert {item["check_id"] for item in checks} == set(ORIGINAL_CHECKS + INVENTORY_CHECKS)
    assert len(checks) == 15
    assert all(item["requires_elevation"] is False for item in checks)
    for check_id in ORIGINAL_CHECKS:
        result = payload(asyncio.run(call("inspect", {"check_id": check_id})))
        assert_result_schema(result, check_id)
        if check_id == "system.services":
            # The disposable image has no running systemd service manager.
            assert result["status"] == "error"
            assert result["exit_code"] != 0
            assert result["error"]
        else:
            assert result["status"] == "success", (check_id, result)
            assert result["exit_code"] == 0


@pytest.mark.parametrize("check_id", INVENTORY_CHECKS)
def test_inventory_checks(check_id):
    result = payload(asyncio.run(call("inspect", {"check_id": check_id})))
    assert_result_schema(result, check_id)
    assert result["status"] == "success", (check_id, result)
    assert result["exit_code"] == 0
    assert result["truncated"] is False
    assert result["error"] is None
    if check_id == "system.block_devices":
        assert isinstance(json.loads(result["output"])["blockdevices"], list)
    elif check_id == "system.filesystems":
        assert result["output"].splitlines()[0].split() == [
            "Filesystem", "Type", "1-blocks", "Used", "Available", "Capacity", "Mounted", "on",
        ]
    elif check_id == "system.mounts":
        assert isinstance(json.loads(result["output"])["filesystems"], list)
    elif check_id == "system.processes":
        lines = result["output"].splitlines()
        assert lines[0].split() == ["PID", "PPID", "USER", "STAT", "COMMAND"]
        assert len(lines) > 1
        assert all(len(line.split()) >= 5 for line in lines[1:])
        assert "--sort=pid" not in result["output"]
    elif check_id == "network.interfaces":
        assert isinstance(json.loads(result["output"]), list)
    else:
        # An empty routing table is a valid successful result.
        assert isinstance(json.loads(result["output"]), list)


def test_batch_multiple_checks():
    result = payload(asyncio.run(call("inspect_batch", {"check_ids": ["system.identity", "system.kernel"]})))
    assert [item["check_id"] for item in result] == ["system.identity", "system.kernel"]
    assert all(item["host"] == "e2e-host" and item["status"] == "success" for item in result)
    assert "uid=" in result[0]["output"]
    assert "Linux" in result[1]["output"]


def test_unsupported_check_rejected():
    result = asyncio.run(call("inspect", {"check_id": "system.os; id"}))
    assert result.is_error


def test_two_hosts_and_routing():
    hosts = payload(asyncio.run(call("list_hosts")))
    assert hosts == [{"host_id": "a", "label": "e2e-host"},
                     {"host_id": "b", "label": "e2e-host-b"}]
    result = payload(asyncio.run(call("inspect", {"check_id": "system.identity", "host_id": "b"})))
    assert result["host_id"] == "b"
    assert result["host"] == "e2e-host-b"
    assert result["status"] == "success"
    assert "uid=" in result["output"]
    batch = payload(asyncio.run(call("inspect_batch", {
        "check_ids": ["system.identity", "system.kernel"], "host_id": "b"})))
    assert all(item["host_id"] == "b" and item["status"] == "success" for item in batch)
    for host_id in ("missing", "b; id", "-oProxyCommand=id"):
        assert asyncio.run(call("inspect", {"check_id": "system.identity", "host_id": host_id})).is_error


def test_cross_host_credentials_rejected():
    wrong_key = ssh("identity", key="/run/fixture/key_b")
    assert wrong_key.returncode == 255
    wrong_host_key = ssh("identity", known_hosts="/run/fixture/known_hosts_b")
    assert wrong_host_key.returncode == 255


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


@pytest.mark.parametrize("command", (
    "system.block_devices --output SERIAL", "system.filesystems /etc/shadow",
    "system.mounts; id", "system.processes --forest",
    "network.interfaces; id", "network.routes_ipv4 -j", "network.routes_ipv6 && id",
))
def test_inventory_arguments_rejected_by_force_command(command):
    result = ssh(command)
    assert result.returncode == 126
    assert b"DENIED" in result.stderr


def test_unavailable_ssh_server():
    result = payload(asyncio.run(asyncio.wait_for(
        call("inspect", {"check_id": "system.os"}), timeout=20,
    )))
    assert result["status"] == "error"
    assert_result_schema(result, "system.os")
    assert result["exit_code"] != 0
    assert result["error"]
    assert "PRIVATE KEY" not in json.dumps(result)
    other = payload(asyncio.run(call("inspect", {"check_id": "system.identity", "host_id": "b"})))
    assert other["host_id"] == "b"
    assert other["status"] == "success"
