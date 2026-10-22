"""Client-facing metadata for the fixed diagnostic protocol."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Check:
    description: str
    category: str
    requires_elevation: bool = False
    timeout_seconds: int = 15
    max_output_bytes: int = 16384


CHECKS = {
    "system.identity": Check("Current SSH account identity", "system"),
    "system.uptime": Check("Host uptime and load", "system"),
    "network.listeners": Check("Listening TCP sockets", "network"),
    "system.services": Check("Running systemd services", "system"),
    "system.os": Check("Operating system release metadata", "system"),
    "system.kernel": Check("Kernel and machine information", "system"),
    "system.cpu": Check("CPU architecture and topology", "system"),
    "system.memory": Check("Memory usage in bytes", "system"),
}

LEGACY_OPERATIONS = {
    "identity": "system.identity",
    "uptime": "system.uptime",
    "listeners": "network.listeners",
    "services": "system.services",
}
