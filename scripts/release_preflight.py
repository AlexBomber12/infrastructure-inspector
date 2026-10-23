#!/usr/bin/env python3
"""Local, read-only release checks. No production network or container changes."""

import argparse
import copy
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "inspector"))
from hosts import valid_target

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.3.0"
SECRET_TARGETS = {
    "inspector": {"/run/secrets/sg-audit-ed25519", "/run/secrets/ssh-known-hosts"},
    "tunnel-client": {"/run/secrets/control-plane-api-key"},
}
SSH_OPTIONS = {
    "StrictHostKeyChecking=yes", "IdentitiesOnly=yes", "IdentityAgent=none",
    "BatchMode=yes", "GlobalKnownHostsFile=/dev/null", "UpdateHostKeys=no",
    "ClearAllForwardings=yes", "HostKeyAlgorithms=ssh-ed25519",
}
PROBE = """import json, server, catalog, bounded, hosts
from hosts import Host
modules = [server, catalog, bounded, hosts]
command = server._ssh_command('identity', Host('default', 'fixture', 'audit@fixture', '/tmp/key', '/tmp/known'))
print(json.dumps({'modules': [m.__file__ for m in modules], 'command': command}))
"""


def require(condition, message):
    if not condition:
        raise ValueError(message)


def run(*args):
    result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, check=False)
    require(result.returncode == 0, f"Local command failed: {args[0]} {args[1]}")
    return result.stdout.strip()


def validate_revision(expected_revision):
    require(re.fullmatch(r"[0-9a-f]{40}", expected_revision) is not None,
            "Expected revision must be a full commit SHA")


def _runtime_contract(config):
    """Keep runtime fields while masking approved operator-owned values."""
    contract = copy.deepcopy(config)
    contract.pop("name", None)
    for network in contract["networks"].values():
        network.pop("name", None)
    private = contract["networks"]["mcp-private"]
    pools = private["ipam"]["config"]
    require(len(pools) == 1 and set(pools[0]) == {"subnet", "gateway"},
            "Private network address configuration changed")
    try:
        subnet = ipaddress.ip_network(pools[0]["subnet"], strict=False)
        gateway = ipaddress.ip_address(pools[0]["gateway"])
    except ValueError as exc:
        raise ValueError("Invalid private network address configuration") from exc
    require(gateway in subnet, "Private network gateway is outside subnet")
    pools[0] = {"subnet": "<operator-subnet>", "gateway": "<operator-gateway>"}
    for service in contract["services"].values():
        for mount in service.get("volumes", []):
            mount["source"] = "<operator-path>"
        service["volumes"] = sorted(service.get("volumes", []), key=lambda mount: mount["target"])
    inspector = contract["services"]["inspector"]
    inspector["image"] = "<verified-image-id>"
    inspector["environment"] = {key: "<operator-value>" for key in inspector["environment"]}
    tunnel = contract["services"]["tunnel-client"]
    tunnel["command"][0] = "--control-plane.tunnel-id=<operator-id>"
    return contract


def validate_compose(config, approved, expected_id):
    services = config["services"]
    require(set(services) == {"inspector", "tunnel-client"}, "Unexpected Compose services")
    inspector = services["inspector"]
    require(inspector.get("image") == expected_id, "Compose release image ID mismatch")
    require(inspector.get("build") is None and inspector.get("pull_policy") == "never",
            "Inspector must use a local image without a build")
    require(inspector.get("user") == "65533:65533" and inspector.get("read_only") is True,
            "Inspector must be non-root and read-only")
    require(inspector.get("privileged") is not True and inspector.get("cap_drop") == ["ALL"],
            "Inspector privileges changed")
    require(not inspector.get("cap_add") and not inspector.get("devices")
            and inspector.get("pid") != "host" and inspector.get("ipc") != "host",
            "Inspector device or namespace privileges changed")
    require("no-new-privileges:true" in inspector.get("security_opt", []),
            "Inspector no-new-privileges setting missing")
    environment = inspector.get("environment", {})
    require(set(environment) == {"INSPECTOR_SSH_TARGET", "INSPECTOR_HOST_LABEL"},
            "Single-host Inspector environment changed")
    require(valid_target(environment["INSPECTOR_SSH_TARGET"], legacy=True),
            "Inspector SSH target is missing or unsafe")
    label = environment["INSPECTOR_HOST_LABEL"]
    require(isinstance(label, str) and bool(label.strip()),
            "Inspector host label is missing")
    require("ssh-egress" not in config.get("networks", {}) and
            set(inspector.get("networks", {})) == {"mcp-private"},
            "Single-host network changed")
    require(config["networks"]["mcp-private"].get("internal") is True,
            "Private network must remain internal")
    require(inspector.get("ports") is None and inspector.get("network_mode") is None,
            "Inspector must not publish ports or use host networking")
    for service_name, targets in SECRET_TARGETS.items():
        mounts = services[service_name].get("volumes", [])
        require({v["target"] for v in mounts} == targets,
                f"Required secret mounts differ for {service_name}")
        for mount in mounts:
            require(mount.get("type") == "bind" and mount.get("read_only") is True,
                    "Secret mounts must be read-only binds")
            require(mount.get("bind", {}).get("create_host_path") is not True,
                    "Secret mounts must not create host paths")
            source = Path(mount["source"])
            require(source.is_absolute() and source.is_file() and not source.is_symlink()
                    and source.stat().st_size > 0,
                    f"Required local secret file missing: {mount['target']}")
            require("docker.sock" not in mount["source"] and "docker.sock" not in mount["target"],
                    "Docker socket mount is forbidden")
    tunnel = services["tunnel-client"]
    require(tunnel.get("privileged") is not True and tunnel.get("read_only") is True
            and not tunnel.get("cap_add") and not tunnel.get("devices"),
            "Tunnel container privileges changed")
    command = tunnel.get("command")
    require(isinstance(command, list) and len(command) == 4
            and isinstance(command[0], str)
            and re.fullmatch(r"--control-plane\.tunnel-id=[A-Za-z0-9_-]+", command[0]),
            "Tunnel ID is missing or unsafe")
    require(_runtime_contract(config) == _runtime_contract(approved),
            "Release Compose runtime contract differs from approved configuration")


def validate_image(metadata, expected_id, expected_revision, probe):
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", expected_id) is not None,
            "Expected image ID must be a full sha256 identifier")
    require(metadata["Id"] == expected_id, "Release image ID mismatch")
    labels = metadata["Config"].get("Labels") or {}
    require(labels.get("org.opencontainers.image.version") == VERSION,
            "Release image version label mismatch")
    require(labels.get("org.opencontainers.image.revision") == expected_revision,
            "Release image source revision mismatch")
    require(metadata["Config"].get("User") == "65533:65533",
            "Release image user changed")
    require(metadata["Config"].get("Cmd") == ["python", "server.py"]
            and metadata["Config"].get("Entrypoint") is None,
            "Release image startup command changed")
    require(all(path.startswith("/opt/ssh-inspector/") for path in probe["modules"])
            and len(probe["modules"]) == 4, "Release image application modules missing")
    command = probe["command"]
    require(command[:4] == ["/usr/bin/ssh", "-F", "/dev/null", "-T"]
            and command[-2:] == ["audit@fixture", "identity"],
            "SSH command structure changed")
    require(all(option in command for option in SSH_OPTIONS)
            and "UserKnownHostsFile=/tmp/known" in command,
            "SSH client restrictions changed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True, help="Expected full source commit SHA")
    parser.add_argument("--image-id", required=True, help="Expected local sha256 image ID")
    parser.add_argument("--env-file", type=Path, required=True,
                        help="Local production Compose env file; contents are never printed")
    parser.add_argument("--compose-file", type=Path, required=True,
                        help="Exact local Compose file intended for deployment")
    args = parser.parse_args()
    try:
        validate_revision(args.revision)
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", args.image_id) is not None,
                "Expected image ID must be a full sha256 identifier")
        require(args.env_file.is_file(), "Local Compose env file is missing")
        require(args.compose_file.is_file(), "Deployment Compose file is missing")
        config = json.loads(run("docker", "compose", "--env-file", str(args.env_file),
                                "-f", str(args.compose_file.resolve()), "config", "--format", "json"))
        approved = json.loads(run("docker", "compose", "--env-file", str(ROOT / ".env.example"),
                                  "-f", str(ROOT / "compose.yaml"), "config", "--format", "json"))
        validate_compose(config, approved, args.image_id)
        metadata = json.loads(run("docker", "image", "inspect", args.image_id))[0]
        probe = json.loads(run("docker", "run", "--rm", "--network", "none", "--read-only",
                               "--user", "65533:65533", "--entrypoint", "python",
                               metadata["Id"], "-c", PROBE))
        validate_image(metadata, args.image_id, args.revision, probe)
    except (ValueError, KeyError, IndexError, json.JSONDecodeError, OSError) as exc:
        print(f"Release preflight failed: {exc}", file=sys.stderr)
        return 1
    print(f"Release preflight passed: {VERSION} at {args.revision}, image {args.image_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
