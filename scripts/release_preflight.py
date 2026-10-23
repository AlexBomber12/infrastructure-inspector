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
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "inspector"))
from hosts import LABEL, valid_target

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.3.0"
COMPOSE_VARIABLES = {
    "INSPECTOR_IMAGE_ID", "INSPECTOR_SSH_TARGET", "INSPECTOR_HOST_LABEL",
    "INSPECTOR_SSH_KEY_PATH", "INSPECTOR_KNOWN_HOSTS_PATH",
    "INSPECTOR_DOCKER_SUBNET", "INSPECTOR_DOCKER_GATEWAY",
    "OPENAI_TUNNEL_ID", "OPENAI_TUNNEL_API_KEY_PATH", "COMPOSE_PROJECT_NAME",
}
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
SECRET_META_PROBE = """import json, os, stat, sys
try:
    entry = os.lstat('/source-parent/' + sys.argv[1])
    if not stat.S_ISREG(entry.st_mode) or entry.st_size == 0:
        sys.exit(1)
    print(json.dumps([entry.st_dev, entry.st_ino]))
except OSError:
    sys.exit(1)
"""
SECRET_ACCESS_PROBE = """import json, os, stat, sys
try:
    fd = os.open('/source-file', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    mounted = os.fstat(fd)
    os.close(fd)
    if not stat.S_ISREG(mounted.st_mode) or mounted.st_size == 0:
        sys.exit(1)
    print(json.dumps([mounted.st_dev, mounted.st_ino]))
except OSError:
    sys.exit(1)
"""


def require(condition, message):
    if not condition:
        raise ValueError(message)


def run(*args):
    result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, check=False)
    require(result.returncode == 0, f"Local command failed: {args[0]} {args[1]}")
    return result.stdout.strip()


def validate_revisions(image_revision, deployment_revision):
    require(re.fullmatch(r"[0-9a-f]{40}", image_revision) is not None,
            "Expected image source revision must be a full commit SHA")
    require(re.fullmatch(r"[0-9a-f]{40}", deployment_revision) is not None,
            "Expected deployment revision must be a full commit SHA")
    require(run("git", "rev-parse", "HEAD") == deployment_revision,
            "Deployment checkout differs from reviewed revision")
    require(not run("git", "status", "--porcelain"), "Release checkout is dirty")


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
    require(isinstance(label, str) and LABEL.fullmatch(label) is not None,
            "Inspector host label is missing or unsafe")
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
            require(source.is_absolute() and source.name not in ("", ".", ".."),
                    f"Required secret source is invalid: {mount['target']}")
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


def validate_secrets(config, image_id):
    """Use Docker's bind resolution; host-side stat cannot cross protected parents."""
    for service_name, targets in SECRET_TARGETS.items():
        service = config["services"][service_name]
        uid, gid = service["user"].split(":")
        for mount in service["volumes"]:
            source = Path(mount["source"])
            target = mount["target"]
            require(target in targets and source.is_absolute()
                    and not any(char in str(source) for char in ',\n\r"'),
                    f"Required secret source is invalid: {target}")
            identities = []
            message = (f"Required secret is missing, unsafe, empty, or inaccessible "
                       f"to {service_name}: {target}")
            for user, bind, script, args in (
                ("0:0", f"type=bind,src={source.parent},dst=/source-parent,readonly",
                 SECRET_META_PROBE, (source.name,)),
                (f"{uid}:{gid}", f"type=bind,src={source},dst=/source-file,readonly",
                 SECRET_ACCESS_PROBE, ())
            ):
                probe_name = f"release-preflight-{uuid.uuid4().hex}"
                command = ("docker", "run", "--rm", "--name", probe_name,
                     "--network", "none", "--read-only",
                     "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                     "--pids-limit", "32", "--memory", "128m", "--user", user,
                     "--mount", bind, "--entrypoint", "python", image_id,
                     "-c", script, *args)
                try:
                    result = subprocess.run(command, cwd=ROOT, capture_output=True,
                                            text=True, check=False, timeout=30)
                except subprocess.TimeoutExpired:
                    try:
                        cleanup = subprocess.run(
                            ("docker", "container", "rm", "--force", probe_name),
                            cwd=ROOT, capture_output=True, timeout=5, check=False)
                    except (OSError, subprocess.TimeoutExpired):
                        cleanup = None
                    if cleanup is None or cleanup.returncode != 0:
                        raise ValueError(
                            f"{message} (probe timed out; cleanup unverified for disposable "
                            f"container {probe_name}; inspect or remove that container manually)") from None
                    raise ValueError(f"{message} (probe timed out; disposable container "
                                     f"{probe_name} removed)") from None
                require(result.returncode == 0, message)
                identity = json.loads(result.stdout)
                require(isinstance(identity, list) and len(identity) == 2
                        and all(isinstance(value, int) for value in identity), message)
                identities.append(identity)
            require(identities[0] == identities[1],
                    f"Required secret mount source changed or is unsafe: {target}")


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
    parser.add_argument("--revision", required=True, help="Expected full image source commit SHA")
    parser.add_argument("--deployment-revision", required=True,
                        help="Reviewed full commit SHA for this Compose file and preflight")
    parser.add_argument("--image-id", required=True, help="Expected local sha256 image ID")
    parser.add_argument("--env-file", type=Path, required=True,
                        help="Local production Compose env file; contents are never printed")
    parser.add_argument("--compose-file", type=Path, required=True,
                        help="Exact local Compose file intended for deployment")
    parser.add_argument("--project-name", required=True,
                        help="Compose project name recorded from the running containers")
    args = parser.parse_args()
    try:
        require(not COMPOSE_VARIABLES.intersection(os.environ),
                "Unset exported Compose deployment variables before preflight")
        validate_revisions(args.revision, args.deployment_revision)
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", args.image_id) is not None,
                "Expected image ID must be a full sha256 identifier")
        require(args.env_file.is_file(), "Local Compose env file is missing")
        require(args.compose_file.is_file(), "Deployment Compose file is missing")
        config = json.loads(run("docker", "compose", "--env-file", str(args.env_file),
                                "-f", str(args.compose_file.resolve()), "-p", args.project_name,
                                "config", "--format", "json"))
        require(config.get("name") == args.project_name,
                "Effective Compose project differs from the running deployment")
        approved = json.loads(run("docker", "compose", "--env-file", str(ROOT / ".env.example"),
                                  "-f", str(ROOT / "compose.yaml"), "config", "--format", "json"))
        validate_compose(config, approved, args.image_id)
        metadata = json.loads(run("docker", "image", "inspect", args.image_id))[0]
        probe = json.loads(run("docker", "run", "--rm", "--network", "none", "--read-only",
                               "--user", "65533:65533", "--entrypoint", "python",
                               metadata["Id"], "-c", PROBE))
        validate_image(metadata, args.image_id, args.revision, probe)
        validate_secrets(config, metadata["Id"])
    except (ValueError, KeyError, IndexError, json.JSONDecodeError, OSError) as exc:
        print(f"Release preflight failed: {exc}", file=sys.stderr)
        return 1
    print(f"Release preflight passed: {VERSION} at {args.revision}, image {args.image_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
