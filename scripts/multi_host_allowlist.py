#!/usr/bin/env python3
"""Authorize the systemd SSH allowlist from Inspector's effective registry mount."""

import ipaddress
from pathlib import Path
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "inspector"))
from hosts import load_multi_registry


def validate(source, secrets, gateway, private_subnet, egress_subnet, allowlist):
    """Require exact, unambiguous external destinations from the mounted registry."""
    source = Path(source)
    secrets = Path(secrets)
    if not source.is_absolute() or not secrets.is_absolute() or source.resolve(strict=True) != source:
        raise ValueError("Unsafe mounted registry source")
    metadata = source.stat()
    readable_by_inspector = (bool(metadata.st_mode & stat.S_IROTH) or
                             (metadata.st_uid == 65533 and bool(metadata.st_mode & stat.S_IRUSR)) or
                             (metadata.st_gid == 65533 and bool(metadata.st_mode & stat.S_IRGRP)))
    if metadata.st_mode & 0o022 or not readable_by_inspector:
        raise ValueError("Unsafe registry permissions")
    registry = load_multi_registry(source, secrets)
    if registry.default_host != "default":
        raise ValueError("Unexpected default host")
    gateway = ipaddress.IPv4Address(gateway)
    private = ipaddress.IPv4Network(private_subnet)
    egress = ipaddress.IPv4Network(egress_subnet)
    if gateway not in private:
        raise ValueError("Invalid private gateway")

    def address(target):
        return ipaddress.IPv4Address(target.rsplit("@", 1)[1])

    if address(registry.hosts["default"].target) != gateway:
        raise ValueError("Default host is not the private gateway")
    approved = [address(host.target) for host_id, host in registry.hosts.items()
                if host_id != "default"]
    if not approved or len(approved) != len(set(approved)) or any(
            item in private or item in egress for item in approved):
        raise ValueError("Invalid external host destinations")
    configured = [ipaddress.IPv4Address(item) for item in allowlist]
    if len(configured) != len(set(configured)) or set(configured) != set(approved):
        raise ValueError("External SSH allowlist differs from registry")


def main(argv):
    try:
        if len(argv) < 6:
            raise ValueError("Missing allowlist arguments")
        validate(*argv[:5], argv[5:])
    except (ValueError, OSError, RuntimeError, TypeError, IndexError):
        print("Multi-host Inspector lifecycle: mounted registry and external SSH "
              "allowlist are invalid or differ; policy retained", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
