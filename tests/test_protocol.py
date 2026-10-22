"""MCP SDK client coverage of the real Streamable HTTP transport."""
import asyncio
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from catalog import CHECKS


def payload(result):
    if result.structured_content is not None:
        return result.structured_content.get("result", result.structured_content)
    return json.loads(result.content[0].text)


def test_streamable_http_protocol():
    with tempfile.TemporaryDirectory() as directory:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        log = Path(directory) / "executions"
        log.touch()
        env = dict(os.environ, PROTOCOL_PORT=str(port), PROTOCOL_LOG=str(log))
        process = subprocess.Popen(
            [sys.executable, str(Path(__file__).with_name("protocol_server.py"))],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise AssertionError(process.stderr.read().decode())
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                raise AssertionError("MCP server did not start")
            asyncio.run(_exercise(f"http://127.0.0.1:{port}/mcp", log))
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            process.stderr.close()


async def _exercise(url, log):
    async with streamable_http_client(url) as (read, write):
        async with ClientSession(read, write) as session:
            initialized = await session.initialize()
            assert initialized.server_info.name == "ssh-inspector-dev"
            tools = {tool.name: tool for tool in (await session.list_tools()).tools}
            assert set(tools) == {"inspector_status", "list_checks", "inspect", "inspect_batch", "inspect_server"}
            assert "check_id" in tools["inspect"].input_schema["properties"]
            assert "check_ids" in tools["inspect_batch"].input_schema["properties"]
            status = payload(await session.call_tool("inspector_status"))
            assert "identity" in status["operations"]
            checks = payload(await session.call_tool("list_checks"))
            assert len(checks) == 15
            assert {item["check_id"] for item in checks} == set(CHECKS)
            assert all(item["requires_elevation"] is False for item in checks)
            single = payload(await session.call_tool("inspect", {"check_id": "system.os"}))
            assert single["host"] == "protocol-fixture"
            assert single["status"] == "success"
            assert single["output"] == "system.os\n"
            for check_id in (
                "system.block_devices", "system.filesystems", "system.mounts",
                "system.processes", "network.interfaces", "network.routes_ipv4",
                "network.routes_ipv6",
            ):
                result = payload(await session.call_tool("inspect", {"check_id": check_id}))
                assert result["check_id"] == check_id
                assert result["status"] == "success"
                assert result["output"] == check_id + "\n"
            batch = payload(await session.call_tool("inspect_batch", {"check_ids": ["system.os", "system.memory"]}))
            assert [item["status"] for item in batch] == ["success", "error"]
            assert batch[1]["error"] == "fixture failure"
            legacy = payload(await session.call_tool("inspect_server", {"operation": "uptime"}))
            assert legacy["operation"] == "uptime"
            before = log.read_text()
            for name, args in (
                ("inspect", {"check_id": "system.os; id"}),
                ("inspect", {"check_id": 42}),
                ("inspect", {"check_id": "system.processes --forest"}),
                ("inspect", {"check_id": "network.routes_ipv6; id"}),
                ("inspect_batch", {"check_ids": ["system.os", "bad"]}),
                ("inspect_batch", {"check_ids": []}),
                ("inspect_server", {"operation": "id; true"}),
            ):
                result = await session.call_tool(name, args)
                assert result.is_error, (name, result)
            assert log.read_text() == before
