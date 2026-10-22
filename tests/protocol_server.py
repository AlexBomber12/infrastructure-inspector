"""Disposable MCP transport with a controlled SSH execution boundary."""
import os
from pathlib import Path

from mcp.server.transport_security import TransportSecuritySettings

import server
from bounded import Captured


def fake_ssh(command, **_):
    with Path(os.environ["PROTOCOL_LOG"]).open("a", encoding="utf-8") as log:
        log.write(command[-1] + "\n")
    if command[-1] == "system.memory":
        return Captured(1, b"", b"fixture failure", False)
    return Captured(0, (command[-1] + "\n").encode(), b"", False)


server.run_bounded = fake_ssh
server.SSH_TARGET = "fixture@localhost"
server.HOST_LABEL = "protocol-fixture"
port = int(os.environ["PROTOCOL_PORT"])
server.mcp.run(
    transport="streamable-http", host="127.0.0.1", port=port,
    stateless_http=True, json_response=True,
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[f"127.0.0.1:{port}"], allowed_origins=[],
    ),
)
