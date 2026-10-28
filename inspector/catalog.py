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
    "gpu.nvidia.status": Check("NVIDIA GPU metrics as raw CSV", "gpu"),
    "gpu.nvidia.compute_processes": Check("NVIDIA compute process IDs and GPU memory as raw CSV", "gpu"),
    "system.identity": Check("Current SSH account identity", "system"),
    "system.uptime": Check("Host uptime and load", "system"),
    "network.listeners": Check("Listening TCP sockets", "network"),
    "system.services": Check("Running systemd services", "system"),
    "system.os": Check("Operating system release metadata", "system"),
    "system.kernel": Check("Kernel and machine information", "system"),
    "system.cpu": Check("CPU architecture and topology", "system"),
    "system.memory": Check("Memory usage in bytes", "system"),
    "system.block_devices": Check("Block device names, sizes, filesystems, mountpoints, models and transport", "system"),
    "system.filesystems": Check("Filesystem capacity and usage in bytes", "system"),
    "system.mounts": Check("Mounted filesystem targets, sources and types", "system"),
    "system.processes": Check("Process IDs, parents, users, states and names", "system"),
    "network.interfaces": Check("Network interfaces and addresses", "network"),
    "network.routes_ipv4": Check("IPv4 routing table", "network"),
    "network.routes_ipv6": Check("IPv6 routing table", "network"),
}

LEGACY_OPERATIONS = {
    "identity": "system.identity",
    "uptime": "system.uptime",
    "listeners": "network.listeners",
    "services": "system.services",
}
