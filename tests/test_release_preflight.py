"""Hermetic validation of the operator's local release preflight."""

import importlib.util
import copy
import json
from pathlib import Path
import runpy
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/release_preflight.py"
spec = importlib.util.spec_from_file_location("release_preflight", SCRIPT)
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)
policy_spec = importlib.util.spec_from_file_location(
    "network_policy_verify", SCRIPT.with_name("network_policy_verify.py"))
policy_verify = importlib.util.module_from_spec(policy_spec)
policy_spec.loader.exec_module(policy_verify)


@pytest.fixture
def config(tmp_path):
    config = json.loads((Path(__file__).with_name("fixtures") /
                         "compose-single-effective.json").read_text())
    for service in config["services"].values():
        for mount in service.get("volumes", []):
            source = tmp_path / mount["target"].rsplit("/", 1)[-1]
            source.write_text("fixture")
            mount["source"] = str(source)
    return config


@pytest.fixture
def multi_config(tmp_path):
    value = json.loads((Path(__file__).with_name("fixtures") /
                        "compose-multi-effective.json").read_text())
    for service in value["services"].values():
        for mount in service.get("volumes", []):
            mount["source"] = str(tmp_path / mount["target"].rsplit("/", 1)[-1])
    return value


def test_multi_host_compose_contract(multi_config):
    approved = copy.deepcopy(multi_config)
    image = multi_config["services"]["inspector"]["image"]
    preflight.validate_compose(multi_config, approved, image)
    inspector = multi_config["services"]["inspector"]
    inspector["environment"] = {"INSPECTOR_HOST_MODE": "legacy"}
    with pytest.raises(ValueError, match="Multi-host Inspector environment"):
        preflight.validate_compose(multi_config, approved, image)
    inspector["environment"] = {"INSPECTOR_HOST_MODE": "multi"}
    inspector["dns"] = ["8.8.8.8"]
    with pytest.raises(ValueError, match="DNS sink"):
        preflight.validate_compose(multi_config, approved, image)
    inspector["dns"] = ["127.0.0.254"]
    inspector["networks"].pop("ssh-egress")
    with pytest.raises(ValueError, match="Multi-host networks"):
        preflight.validate_compose(multi_config, approved, image)
    inspector["networks"] = copy.deepcopy(approved["services"]["inspector"]["networks"])
    inspector["volumes"].pop()
    with pytest.raises(ValueError, match="mounts differ"):
        preflight.validate_compose(multi_config, approved, image)


def test_multi_host_network_rejections(multi_config):
    preflight.validate_multi_networks(multi_config)
    cases = [
        (("networks", "ssh-egress", "enable_ipv6"), True, "disable IPv6"),
        (("networks", "ssh-egress", "driver_opts", "com.docker.network.bridge.enable_icc"), "true", "communication"),
        (("networks", "ssh-egress", "driver_opts", "com.docker.network.bridge.name"), "bad bridge!", "bridge name"),
        (("services", "inspector", "networks", "mcp-private", "mac_address"), "aa:bb:cc:dd:ee:ff", "private MAC"),
        (("networks", "ssh-egress", "ipam", "config", 0, "subnet"), "bad", "Invalid multi-host"),
        (("networks", "ssh-egress", "ipam", "config", 0, "subnet"), "172.30.240.0/24", "distinct IPv4"),
        (("services", "inspector", "networks", "ssh-egress", "ipv4_address"), "172.30.241.1", "usable"),
        (("services", "inspector", "networks", "ssh-egress", "ipv4_address"), "172.30.241.255", "usable"),
    ]
    for path, value, message in cases:
        item = multi_config
        for key in path[:-1]:
            item = item[key]
        key = path[-1]
        old = item[key]
        item[key] = value
        with pytest.raises(ValueError, match=message):
            preflight.validate_multi_networks(multi_config)
        item[key] = old


def test_multi_host_secret_probes(multi_config):
    image = multi_config["services"]["inspector"]["image"]
    with patch.object(preflight.subprocess, "run", return_value=SimpleNamespace(
        returncode=0, stdout="[1,2]")) as calls:
        preflight.validate_secrets(multi_config, image)
    commands = [call.args[0] for call in calls.call_args_list]
    assert len(commands) == 6
    assert len({cmd[4] for cmd in commands}) == 6
    for cmd in commands:
        assert cmd[:4] == ("docker", "run", "--rm", "--name")
        assert "--network" in cmd and cmd[cmd.index("--network") + 1] == "none"
        assert "--read-only" in cmd and "--cap-drop" in cmd
        assert "no-new-privileges:true" in cmd
        assert "--pids-limit" in cmd and "--memory" in cmd
        assert calls.call_args_list[commands.index(cmd)].kwargs["timeout"] == 30
    assert any(preflight.SECRET_DIR_META_PROBE in cmd for cmd in commands)
    assert any(preflight.MULTI_SECRET_PROBE in cmd for cmd in commands)
    with patch.object(preflight.subprocess, "run", side_effect=[
        SimpleNamespace(returncode=0, stdout="[1,2]"),
        SimpleNamespace(returncode=0, stdout="[1,2]"),
        SimpleNamespace(returncode=1, stdout="")
    ]):
        with pytest.raises(ValueError, match="inspector-hosts"):
            preflight.validate_secrets(multi_config, image)
    with patch.object(preflight.subprocess, "run", side_effect=[
        SimpleNamespace(returncode=0, stdout="[1,2]") for _ in range(5)
    ] + [SimpleNamespace(returncode=1, stdout="")]):
        with pytest.raises(ValueError, match="registry or per-host credentials"):
            preflight.validate_secrets(multi_config, image)


def test_multi_host_migration_requires_current_snapshot(multi_config, tmp_path):
    compose = tmp_path / "compose.yaml"
    env = tmp_path / "deploy.env"
    with pytest.raises(ValueError, match="fresh single-host"):
        preflight.validate_migration(multi_config, compose, env, "project", None)
    (tmp_path / "tunnel-container-id").write_text("tunnel-id")
    (tmp_path / "project-name").write_text("project")
    multi_config["name"] = "project"
    attachments = {multi_config["networks"][name]["name"]: {}
                   for name in ("mcp-private", "control-plane")}
    private_network = {"Internal": True, "EnableIPv6": False,
                       "IPAM": {"Config": [{"Subnet": "172.30.240.0/24",
                                            "Gateway": "172.30.240.1"}]}}
    with patch.object(preflight, "run", side_effect=["", "hash", "tunnel-client hash",
                                                        json.dumps(attachments),
                                                        json.dumps([private_network])]):
        preflight.validate_migration(multi_config, compose, env, "project", tmp_path)
    (tmp_path / "project-name").write_text("other")
    with patch.object(preflight, "run", return_value=""):
        with pytest.raises(ValueError, match="snapshot project"):
            preflight.validate_migration(multi_config, compose, env, "project", tmp_path)
    (tmp_path / "project-name").write_text("project")
    with patch.object(preflight, "run", side_effect=["", "hash", "tunnel-client other"]):
        with pytest.raises(ValueError, match="running Tunnel"):
            preflight.validate_migration(multi_config, compose, env, "project", tmp_path)
    multi_config["name"] = "other"
    with patch.object(preflight, "run", side_effect=["", "hash", "tunnel-client hash",
                                                        json.dumps(attachments)]):
        with pytest.raises(ValueError, match="Migration project"):
            preflight.validate_migration(multi_config, compose, env, "project", tmp_path)
    multi_config["name"] = "project"
    with patch.object(preflight, "run", side_effect=["", "hash", "tunnel-client hash",
                                                        json.dumps({})]):
        with pytest.raises(ValueError, match="network attachments"):
            preflight.validate_migration(multi_config, compose, env, "project", tmp_path)
    with patch.object(preflight, "run", side_effect=["", "hash", "tunnel-client hash",
                                                        json.dumps(attachments),
                                                        json.dumps([{**private_network, "EnableIPv6": True}])]):
        with pytest.raises(ValueError, match="IPv4-only"):
            preflight.validate_migration(multi_config, compose, env, "project", tmp_path)
    with patch.object(preflight, "run", side_effect=["", "hash", "tunnel-client hash",
                                                        json.dumps(attachments),
                                                        json.dumps([{**private_network,
                                                                     "IPAM": {"Config": []}}])]):
        with pytest.raises(ValueError, match="address pool"):
            preflight.validate_migration(multi_config, compose, env, "project", tmp_path)


@pytest.mark.parametrize("ipam", [
    {"Config": [{"Subnet": "172.22.0.0/16", "Gateway": "172.22.0.1",
                 "IPRange": "172.22.1.0/24"}]},
    {"Config": [{"Subnet": "172.23.0.0/16", "Gateway": "172.22.0.1", "IPRange": ""}]},
    {"Config": [{"Subnet": "172.22.0.0/16", "Gateway": "172.22.0.2", "IPRange": ""}]},
    {"Config": [{"Subnet": "172.22.0.0/16", "Gateway": "172.22.0.1", "IPRange": ""},
                {"Subnet": "172.23.0.0/16", "Gateway": "172.23.0.1"}]},
    {"Config": [{"Subnet": "bad", "Gateway": "172.22.0.1"}]},
    {"Config": [{"Subnet": "172.22.0.0/16", "Gateway": "bad"}]},
    {"Config": [{"Subnet": "172.22.0.0/16", "Gateway": "2001:db8::1"}]},
    {"Config": [{"Subnet": "2001:db8::/64", "Gateway": "2001:db8::1"}]},
    {"Config": [{"Subnet": "172.22.0.0/16"}]},
    {"Config": [{"Gateway": "172.22.0.1"}]},
    {"Config": [{"Subnet": "172.22.0.0/16", "Gateway": None}]},
    {"Config": [{"Subnet": "172.22.0.0/16", "Gateway": "172.22.0.1",
                 "AuxAddress": {"reserved": "172.22.0.5"}}]},
    {"Config": [{"Subnet": "172.22.0.0/16", "Gateway": "172.22.0.1",
                 "IPRange": None}]},
    {"Config": [{"Subnet": "172.22.0.0/16", "Gateway": "172.22.0.1"}],
     "Options": {"unapproved": "value"}},
    {"Config": [{"Subnet": "172.22.0.0/16", "Gateway": "172.22.0.1"}],
     "Driver": "unapproved"},
])
def test_migration_rejects_effective_private_pool_drift(multi_config, tmp_path, ipam):
    multi_config["name"] = "project"
    multi_config["networks"]["mcp-private"]["ipam"]["config"][0] = {
        "subnet": "172.22.0.0/16", "gateway": "172.22.0.1"}
    (tmp_path / "tunnel-container-id").write_text("tunnel-id")
    (tmp_path / "project-name").write_text("project")
    attachments = {multi_config["networks"][name]["name"]: {}
                   for name in ("mcp-private", "control-plane")}
    network = {"Internal": True, "EnableIPv6": False, "IPAM": ipam}
    with patch.object(preflight, "run", side_effect=[
        "", "hash", "tunnel-client hash", json.dumps(attachments), json.dumps([network])
    ]), pytest.raises(ValueError, match="(address pool|IPAM settings)"):
        preflight.validate_migration(multi_config, tmp_path / "compose.yaml",
                                     tmp_path / "deploy.env", "project", tmp_path)


def test_multi_egress_subnet_rejects_existing_routes(multi_config):
    with patch.object(preflight, "run", side_effect=[json.dumps([{"ifname": "eth0"}]),
                                                      json.dumps([
        {"dst": "default", "gateway": "192.0.2.1"},
        {"dst": "172.30.240.0/24", "dev": "old-private"}
    ])]):
        preflight.validate_egress_route(multi_config)
    with patch.object(preflight, "run", return_value=json.dumps([{"ifname": "br-insp-example"}])):
        with pytest.raises(ValueError, match="bridge interface already exists"):
            preflight.validate_egress_route(multi_config)
    with patch.object(preflight, "run", side_effect=[json.dumps([]), json.dumps([
        {"dst": "172.30.241.128/25", "dev": "vpn"}
    ])]):
        with pytest.raises(ValueError, match="overlaps"):
            preflight.validate_egress_route(multi_config)


def test_revision_validation():
    with patch.object(preflight, "run", side_effect=["b" * 40, ""]) as run:
        preflight.validate_revisions("a" * 40, "b" * 40)
        assert run.call_args_list[0].args == ("git", "rev-parse", "HEAD")
    with pytest.raises(ValueError, match="image source revision"):
        preflight.validate_revisions("short", "b" * 40)
    with pytest.raises(ValueError, match="deployment revision"):
        preflight.validate_revisions("a" * 40, "short")
    with patch.object(preflight, "run", return_value="c" * 40):
        with pytest.raises(ValueError, match="differs"):
            preflight.validate_revisions("a" * 40, "b" * 40)
    with patch.object(preflight, "run", side_effect=["b" * 40, "modified"]):
        with pytest.raises(ValueError, match="dirty"):
            preflight.validate_revisions("a" * 40, "b" * 40)


def test_local_command_failure_does_not_expose_output():
    with patch.object(preflight.subprocess, "run", return_value=SimpleNamespace(
        returncode=0, stdout="ok\n", stderr="private"
    )):
        assert preflight.run("git", "rev-parse", "HEAD") == "ok"
    with patch.object(preflight.subprocess, "run", return_value=SimpleNamespace(
        returncode=1, stdout="private", stderr="private"
    )):
        with pytest.raises(ValueError, match="Local command failed: git rev-parse"):
            preflight.run("git", "rev-parse", "HEAD")


def test_single_host_compose_contract_and_invalid_release_config(config):
    approved = copy.deepcopy(config)
    preflight.validate_compose(config, approved, approved["services"]["inspector"]["image"])
    inspector = config["services"]["inspector"]
    for field, value in (("image", "infrastructure-inspector:0.2.0"),
                         ("build", {"context": "/obsolete/source"}),
                         ("pull_policy", "always"),
                         ("user", "0:0"), ("read_only", False),
                         ("privileged", True), ("ports", ["8000:8000"]),
                         ("cap_add", ["SYS_ADMIN"]), ("devices", ["/dev/sda"]),
                         ("pid", "host")):
        old = inspector.get(field)
        inspector[field] = value
        with pytest.raises(ValueError):
            preflight.validate_compose(config, approved, approved["services"]["inspector"]["image"])
        if old is None:
            del inspector[field]
        else:
            inspector[field] = old
    inspector["environment"]["INSPECTOR_HOST_MODE"] = "multi"
    with pytest.raises(ValueError, match="environment changed"):
        preflight.validate_compose(config, approved, approved["services"]["inspector"]["image"])
    del inspector["environment"]["INSPECTOR_HOST_MODE"]
    inspector["volumes"][0]["source"] = "/var/run/docker.sock"
    with pytest.raises(ValueError):
        preflight.validate_compose(config, approved, approved["services"]["inspector"]["image"])


def test_secret_mount_must_exist_without_reading(config):
    approved = copy.deepcopy(config)
    source = Path(config["services"]["inspector"]["volumes"][0]["source"])
    source.unlink()
    preflight.validate_compose(config, approved, approved["services"]["inspector"]["image"])
    with patch.object(preflight.subprocess, "run", return_value=SimpleNamespace(returncode=1)):
        with pytest.raises(ValueError, match="missing, unsafe, empty, or inaccessible"):
            preflight.validate_secrets(config, approved["services"]["inspector"]["image"])


def test_secret_mount_rejects_empty_and_symlink(config, tmp_path):
    approved = copy.deepcopy(config)
    source = Path(config["services"]["inspector"]["volumes"][0]["source"])
    source.write_text("")
    preflight.validate_compose(config, approved, approved["services"]["inspector"]["image"])
    source.unlink()
    source.symlink_to(tmp_path / "ssh-known-hosts")
    preflight.validate_compose(config, approved, approved["services"]["inspector"]["image"])


def test_secret_probe_uses_effective_mounts_and_service_identity(config):
    image_id = config["services"]["inspector"]["image"]
    with patch.object(preflight.subprocess, "run", return_value=SimpleNamespace(
        returncode=0, stdout="[1, 2]")) as run:
        preflight.validate_secrets(config, image_id)
    assert run.call_count == 6
    for call in run.call_args_list:
        command = call.args[0]
        assert command[:4] == ("docker", "run", "--rm", "--name")
        assert "none" in command and "--cap-drop" in command
        assert "no-new-privileges:true" in command
        assert preflight.SECRET_META_PROBE in command or preflight.SECRET_ACCESS_PROBE in command
        assert "0:0" in command or "65533:65533" in command or "65532:65532" in command
        assert call.kwargs["timeout"] == 30
    source = config["services"]["inspector"]["volumes"][0]
    source["source"] = "/tmp/bad,source"
    with pytest.raises(ValueError, match="source is invalid"):
        preflight.validate_secrets(config, image_id)
    source["source"] = "relative"
    with pytest.raises(ValueError, match="source is invalid"):
        preflight.validate_compose(config, copy.deepcopy(config), image_id)


@pytest.mark.parametrize("cleanup_result,confirmed", [
    (SimpleNamespace(returncode=0), True),
    (SimpleNamespace(returncode=1, stdout=b"SENSITIVE_BYTES", stderr=b"SENSITIVE_BYTES"), False),
    (OSError("SENSITIVE_BYTES"), False),
    (preflight.subprocess.TimeoutExpired("docker container rm", 5, output=b"SENSITIVE_BYTES"), False),
])
def test_secret_probe_timeout_removes_only_its_disposable_container(
        config, cleanup_result, confirmed):
    image_id = config["services"]["inspector"]["image"]
    timeout = preflight.subprocess.TimeoutExpired("docker", 30)
    with patch.object(preflight.subprocess, "run", side_effect=[timeout, cleanup_result]) as run:
        with pytest.raises(ValueError, match="probe timed out") as error:
            preflight.validate_secrets(config, image_id)
    assert run.call_count == 2
    probe = run.call_args_list[0].args[0]
    cleanup = run.call_args_list[1].args[0]
    assert cleanup == ("docker", "container", "rm", "--force", probe[4])
    assert probe[4].startswith("release-preflight-")
    assert run.call_args_list[1].kwargs["timeout"] == 5
    assert "SENSITIVE_BYTES" not in str(error.value)
    if confirmed:
        assert f"container {probe[4]} removed" in str(error.value)
        assert "cleanup unverified" not in str(error.value)
    else:
        assert f"cleanup unverified for disposable container {probe[4]}" in str(error.value)
        assert "inspect or remove that container manually" in str(error.value)
        assert "removed" not in str(error.value)


@pytest.mark.parametrize("config_kind,probe_index,script", [
    ("single", 0, preflight.SECRET_META_PROBE),
    ("single", 1, preflight.SECRET_ACCESS_PROBE),
    ("multi", 2, preflight.SECRET_DIR_META_PROBE),
    ("multi", 5, preflight.MULTI_SECRET_PROBE),
])
@pytest.mark.parametrize("cleanup_kind", ["success", "nonzero", "oserror", "timeout"])
def test_every_secret_probe_timeout_uses_targeted_cleanup(
        config, multi_config, config_kind, probe_index, script, cleanup_kind):
    selected = config if config_kind == "single" else multi_config
    image_id = selected["services"]["inspector"]["image"]
    seen = []

    def docker_call(command, **kwargs):
        seen.append((command, kwargs))
        if command[:2] == ("docker", "run"):
            if len([item for item, _ in seen if item[:2] == ("docker", "run")]) == probe_index + 1:
                raise preflight.subprocess.TimeoutExpired(
                    command, 30, output=b"SENSITIVE_BYTES", stderr=b"SENSITIVE_BYTES")
            return SimpleNamespace(returncode=0, stdout="[1,2]")
        if cleanup_kind == "oserror":
            raise OSError("SENSITIVE_BYTES")
        if cleanup_kind == "timeout":
            raise preflight.subprocess.TimeoutExpired(command, 5, output=b"SENSITIVE_BYTES")
        return SimpleNamespace(returncode=0 if cleanup_kind == "success" else 1,
                               stdout=b"SENSITIVE_BYTES", stderr=b"SENSITIVE_BYTES")

    with patch.object(preflight.subprocess, "run", side_effect=docker_call):
        with pytest.raises(ValueError, match="probe timed out") as error:
            preflight.validate_secrets(selected, image_id)
    probes = [item for item, _ in seen if item[:2] == ("docker", "run")]
    target = probes[probe_index]
    assert script in target
    assert len({probe[4] for probe in probes}) == len(probes)
    assert seen[-1][0] == ("docker", "container", "rm", "--force", target[4])
    assert seen[-1][1]["timeout"] == 5
    assert "SENSITIVE_BYTES" not in str(error.value)
    if cleanup_kind == "success":
        assert f"container {target[4]} removed" in str(error.value)
    else:
        assert f"cleanup unverified for disposable container {target[4]}" in str(error.value)


def test_secret_probe_start_error_is_sanitized(config):
    image_id = config["services"]["inspector"]["image"]
    with patch.object(preflight.subprocess, "run", side_effect=OSError("SENSITIVE_BYTES")):
        with pytest.raises(ValueError, match="Docker probe could not start") as error:
            preflight.validate_secrets(config, image_id)
    assert "SENSITIVE_BYTES" not in str(error.value)


def test_secret_probe_invalid_metadata_is_sanitized(config):
    image_id = config["services"]["inspector"]["image"]
    with patch.object(preflight.subprocess, "run", return_value=SimpleNamespace(
        returncode=0, stdout="SENSITIVE_BYTES")):
        with pytest.raises(ValueError, match="Required secret") as error:
            preflight.validate_secrets(config, image_id)
    assert "SENSITIVE_BYTES" not in str(error.value)


def test_policy_json_verifier_rejects_mutation_and_normalizes_handles(monkeypatch, capsys):
    args = ["10.240.1.2", "02:42:AC:F0:01:02", "10.240.1.1", "10.240.2.2",
            "br-test-eg", "10.240.3.2"]
    expected = policy_verify.expected_policy(*args[:5], args[5:])
    actual = {"nftables": [{"metainfo": {"version": "1"}},
                           *copy.deepcopy(expected)]}
    for index, item in enumerate(actual["nftables"][1:]):
        next(iter(item.values()))["handle"] = index + 1
    assert policy_verify.verify_policy(actual, expected) is None
    assert policy_verify.normalize("FD42::1") == "fd42::1"
    assert policy_verify.normalize(22) == 22
    assert policy_verify.normalize("br-test-eg") == "br-test-eg"
    for mutate in (lambda policy: policy["nftables"].pop(),
                   lambda policy: policy["nftables"].append({"set": {"name": "extra"}}),
                   lambda policy: policy["nftables"][-1]["rule"].update(chain="other"),
                   lambda policy: policy["nftables"][2]["chain"].update(prio=0)):
        changed = copy.deepcopy(actual)
        mutate(changed)
        with pytest.raises(ValueError):
            policy_verify.verify_policy(changed, expected)
    import io
    monkeypatch.setattr(policy_verify.sys, "stdin", io.StringIO(json.dumps(actual)))
    assert policy_verify.main(args) == 0
    monkeypatch.setattr(policy_verify.sys, "stdin", io.StringIO("{bad"))
    assert policy_verify.main(args) == 1
    assert "installed policy" in capsys.readouterr().err
    monkeypatch.setattr(sys, "argv", [str(SCRIPT.with_name("network_policy_verify.py")), *args])
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(actual)))
    with pytest.raises(SystemExit, match="0"):
        runpy.run_path(str(SCRIPT.with_name("network_policy_verify.py")), run_name="__main__")


def test_secret_mounts_must_belong_to_correct_service(config):
    approved = copy.deepcopy(config)
    inspector = config["services"]["inspector"]
    tunnel = config["services"]["tunnel-client"]
    inspector["volumes"][0], tunnel["volumes"][0] = (
        tunnel["volumes"][0], inspector["volumes"][0])
    with pytest.raises(ValueError, match="mounts differ for inspector"):
        preflight.validate_compose(config, approved, approved["services"]["inspector"]["image"])


@pytest.mark.parametrize("service,field,value", [
    ("inspector", "command", ["sleep", "infinity"]),
    ("inspector", "entrypoint", ["/bin/sh"]),
    ("inspector", "volumes_from", ["tunnel-client"]),
    ("inspector", "tmpfs", []),
    ("inspector", "restart", "no"),
    ("tunnel-client", "entrypoint", ["/bin/sh"]),
    ("tunnel-client", "volumes_from", ["inspector"]),
    ("tunnel-client", "user", "0:0"),
    ("tunnel-client", "read_only", False),
    ("tunnel-client", "cap_drop", []),
    ("tunnel-client", "cap_add", ["SYS_ADMIN"]),
    ("tunnel-client", "devices", ["/dev/sda"]),
    ("tunnel-client", "security_opt", []),
    ("tunnel-client", "ports", ["8000:8000"]),
    ("tunnel-client", "network_mode", "host"),
    ("tunnel-client", "image", "unverified:latest"),
    ("tunnel-client", "depends_on", {}),
])
def test_runtime_service_drift_is_rejected(config, service, field, value):
    approved = copy.deepcopy(config)
    config["services"][service][field] = value
    with pytest.raises(ValueError, match="contract differs|privileges changed"):
        preflight.validate_compose(config, approved, approved["services"]["inspector"]["image"])


@pytest.mark.parametrize("field,value", [
    ("INSPECTOR_SSH_TARGET", None),
    ("INSPECTOR_SSH_TARGET", ""),
    ("INSPECTOR_SSH_TARGET", "-oProxyCommand=id"),
    ("INSPECTOR_SSH_TARGET", "audit@host;id"),
    ("INSPECTOR_HOST_LABEL", None),
    ("INSPECTOR_HOST_LABEL", "  "),
    ("INSPECTOR_HOST_LABEL", "bad\nlabel"),
    ("INSPECTOR_HOST_LABEL", "x" * 65),
])
def test_required_inspector_configuration_is_rejected_when_unsafe(config, field, value):
    approved = copy.deepcopy(config)
    environment = config["services"]["inspector"]["environment"]
    if value is None:
        del environment[field]
    else:
        environment[field] = value
    with pytest.raises(ValueError, match="environment changed|missing or unsafe|label is missing"):
        preflight.validate_compose(config, approved, approved["services"]["inspector"]["image"])


@pytest.mark.parametrize("index,value", [
    (0, "--control-plane.tunnel-id="),
    (1, "--control-plane.api-key=plain:token"),
    (2, "--mcp.server-url=http://elsewhere:8000/mcp"),
    (3, "--health.listen-addr=0.0.0.0:8080"),
])
def test_tunnel_command_drift_is_rejected(config, index, value):
    approved = copy.deepcopy(config)
    config["services"]["tunnel-client"]["command"][index] = value
    with pytest.raises(ValueError, match="Tunnel ID|contract differs"):
        preflight.validate_compose(config, approved, approved["services"]["inspector"]["image"])


def test_network_membership_and_indirect_mounts_are_rejected(config):
    approved = copy.deepcopy(config)
    tunnel = config["services"]["tunnel-client"]
    del tunnel["networks"]["mcp-private"]
    with pytest.raises(ValueError, match="contract differs"):
        preflight.validate_compose(config, approved, approved["services"]["inspector"]["image"])
    tunnel["networks"]["mcp-private"] = None
    config["services"]["inspector"]["volumes_from"] = ["tunnel-client"]
    with pytest.raises(ValueError, match="contract differs"):
        preflight.validate_compose(config, approved, approved["services"]["inspector"]["image"])


def test_valid_operator_values_and_network_address_drift(config, tmp_path):
    approved = copy.deepcopy(config)
    config["name"] = "approved-pilot"
    config["networks"]["control-plane"]["name"] = "pilot-control"
    config["networks"]["mcp-private"]["name"] = "pilot-private"
    config["networks"]["mcp-private"]["ipam"]["config"][0] = {
        "subnet": "10.99.10.0/24", "gateway": "10.99.10.1"}

    config["services"]["inspector"]["environment"] = {
        "INSPECTOR_SSH_TARGET": "ssh://audit@example.com:2222",
        "INSPECTOR_HOST_LABEL": "Pilot host",
    }
    config["services"]["tunnel-client"]["command"][0] = "--control-plane.tunnel-id=tunnel_fixture"
    for service in config["services"].values():
        for mount in service.get("volumes", []):
            source = tmp_path / ("other-" + mount["target"].rsplit("/", 1)[-1])
            source.write_text("fixture")
            mount["source"] = str(source)
    preflight.validate_compose(config, approved, approved["services"]["inspector"]["image"])
    config["networks"]["mcp-private"]["ipam"]["config"][0]["gateway"] = "10.98.10.1"
    with pytest.raises(ValueError, match="gateway is outside"):
        preflight.validate_compose(config, approved, approved["services"]["inspector"]["image"])
    config["networks"]["mcp-private"]["ipam"]["config"][0]["subnet"] = "invalid-subnet"
    with pytest.raises(ValueError, match="Invalid private network"):
        preflight.validate_compose(config, approved, approved["services"]["inspector"]["image"])


def test_image_identity_modules_and_ssh_restrictions():
    image_id = "sha256:" + "a" * 64
    revision = "b" * 40
    metadata = {"Id": image_id, "Config": {"User": "65533:65533",
                                          "Cmd": ["python", "server.py"],
                                          "Entrypoint": None, "Labels": {
        "org.opencontainers.image.version": "0.3.0",
        "org.opencontainers.image.revision": revision,
    }}}
    command = ["/usr/bin/ssh", "-F", "/dev/null", "-T", "-i", "/tmp/key"]
    for option in sorted(preflight.SSH_OPTIONS | {"UserKnownHostsFile=/tmp/known"}):
        command.extend(["-o", option])
    command.extend(["audit@fixture", "identity"])
    probe = {"modules": [f"/opt/ssh-inspector/{name}.py" for name in
                         ("server", "catalog", "bounded", "hosts")], "command": command}
    with patch.object(preflight, "run", return_value=revision):
        preflight.validate_image(metadata, image_id, revision, probe)
        with pytest.raises(ValueError, match="source revision mismatch"):
            preflight.validate_image(metadata, image_id, "c" * 40, probe)
        with pytest.raises(ValueError, match="image ID mismatch"):
            preflight.validate_image(metadata, "sha256:" + "c" * 64, revision, probe)
        metadata["Config"]["Labels"]["org.opencontainers.image.version"] = "0.2.0"
        with pytest.raises(ValueError, match="version label"):
            preflight.validate_image(metadata, image_id, revision, probe)
        metadata["Config"]["Labels"]["org.opencontainers.image.version"] = "0.3.0"
        metadata["Config"]["Cmd"] = ["sleep", "infinity"]
        with pytest.raises(ValueError, match="startup command"):
            preflight.validate_image(metadata, image_id, revision, probe)
        metadata["Config"]["Cmd"] = ["python", "server.py"]
        probe["command"].remove("StrictHostKeyChecking=yes")
        with pytest.raises(ValueError, match="SSH client restrictions"):
            preflight.validate_image(metadata, image_id, revision, probe)


def test_cli_uses_exact_deployment_compose_file(tmp_path, capsys):
    env_file = tmp_path / "private.env"
    compose_file = tmp_path / "approved-compose.yaml"
    for path in (env_file, compose_file):
        path.touch()
    revision = "a" * 40
    image_id = "sha256:" + "b" * 64
    metadata = {"Id": image_id}
    args = ["release_preflight.py", "--revision", revision, "--image-id", image_id,
            "--env-file", str(env_file), "--compose-file", str(compose_file),
            "--project-name", "running-project", "--deployment-revision", "c" * 40]
    with patch.object(sys, "argv", args), patch.object(
        preflight, "validate_revisions"
    ) as validate_revisions, patch.object(preflight, "validate_compose") as validate_compose, patch.object(
        preflight, "validate_image"
    ), patch.object(
        preflight, "run", side_effect=[json.dumps({"name": "running-project", "services": {}}),
                                      json.dumps({"services": {"approved": True}}),
                                      json.dumps([metadata]), json.dumps({"modules": []})]
    ) as run, patch.object(preflight, "validate_secrets") as validate_secrets:
        assert preflight.main() == 0
        validate_revisions.assert_called_once_with(revision, "c" * 40)
        assert run.call_args_list[0].args == (
            "docker", "compose", "--env-file", str(env_file), "-f",
            str(compose_file.resolve()), "-p", "running-project", "config", "--format", "json")
        validate_compose.assert_called_once_with(
            {"name": "running-project", "services": {}}, {"services": {"approved": True}}, image_id)
        validate_secrets.assert_called_once_with({"name": "running-project", "services": {}}, image_id)
    assert "preflight passed" in capsys.readouterr().out
    compose_file.unlink()
    with patch.object(sys, "argv", args), patch.object(preflight, "validate_revisions"):
        assert preflight.main() == 1
    assert "Deployment Compose file is missing" in capsys.readouterr().err


def test_cli_multi_uses_multi_contract_and_snapshot(tmp_path, multi_config):
    env_file = tmp_path / "private.env"
    compose_file = tmp_path / "multi.yaml"
    env_file.touch()
    compose_file.touch()
    project = "ssh-inspector-dev"
    multi_config["name"] = project
    multi_config["networks"]["mcp-private"]["name"] = "ssh-inspector-dev_mcp-private"
    multi_config["networks"]["mcp-private"]["ipam"]["config"][0] = {
        "subnet": "172.22.0.0/16", "gateway": "172.22.0.1"}
    (tmp_path / "tunnel-container-id").write_text("tunnel-id")
    (tmp_path / "project-name").write_text(project)
    attachments = {multi_config["networks"][name]["name"]: {}
                   for name in ("mcp-private", "control-plane")}
    observed_network = {"Internal": True, "EnableIPv6": False, "IPAM": {
        "Driver": "default", "Options": None,
        "Config": [{"Subnet": "172.22.0.0/16", "IPRange": "",
                    "Gateway": "172.22.0.1"}]}}
    image_id = multi_config["services"]["inspector"]["image"]
    args = ["release_preflight.py", "--revision", "a" * 40, "--image-id", image_id,
            "--env-file", str(env_file), "--compose-file", str(compose_file),
            "--project-name", project, "--deployment-revision", "b" * 40,
            "--snapshot", str(tmp_path)]
    with patch.object(sys, "argv", args), patch.object(
        preflight, "validate_revisions"
    ), patch.object(preflight, "validate_compose") as validate_compose, patch.object(
        preflight, "validate_image"
    ), patch.object(preflight, "validate_secrets"), patch.object(preflight, "run", side_effect=[
        json.dumps(multi_config), json.dumps(multi_config),
        json.dumps([{"Id": image_id}]), json.dumps({"modules": []}),
        "", "hash", "tunnel-client hash", json.dumps(attachments),
        json.dumps([observed_network])
    ]) as commands, patch.object(preflight, "validate_egress_route") as route:
        assert preflight.main() == 0
    assert str(preflight.ROOT / ".env.multi.example") in commands.call_args_list[1].args
    validate_compose.assert_called_once()
    assert commands.call_args_list[-1].args == (
        "docker", "network", "inspect", "ssh-inspector-dev_mcp-private")
    route.assert_called_once_with(multi_config)


def test_cli_failure_is_reported_without_secret_contents(tmp_path, capsys):
    env_file = tmp_path / "private.env"
    compose_file = tmp_path / "compose.yaml"
    for path in (env_file, compose_file):
        path.touch()
    args = ["release_preflight.py", "--revision", "a" * 40,
            "--image-id", "sha256:" + "b" * 64, "--env-file", str(env_file),
            "--compose-file", str(compose_file), "--project-name", "running-project",
            "--deployment-revision", "c" * 40]
    with patch.object(sys, "argv", args), patch.object(
        preflight, "validate_revisions"
    ), patch.object(preflight, "run", side_effect=ValueError("invalid Compose")):
        assert preflight.main() == 1
    assert "invalid Compose" in capsys.readouterr().err
    with patch.object(sys, "argv", args), patch.object(
        preflight, "validate_revisions"
    ), patch.object(preflight, "validate_compose"), patch.object(
        preflight, "validate_image"
    ), patch.object(preflight, "validate_secrets", side_effect=ValueError(
        "probe timed out; cleanup unverified for disposable container release-preflight-test"
    )), patch.object(preflight, "run", side_effect=[
        json.dumps({"name": "running-project", "services": {}, "networks": {}}),
        json.dumps({"services": {}}), json.dumps([{"Id": "sha256:" + "b" * 64}]),
        json.dumps({"modules": []})]):
        assert preflight.main() == 1
    assert "cleanup unverified for disposable container" in capsys.readouterr().err
    with patch.object(sys, "argv", args), patch.object(
        preflight, "validate_revisions"
    ), patch.object(preflight, "run", return_value=json.dumps({"name": "wrong-project"})):
        assert preflight.main() == 1
    assert "project differs" in capsys.readouterr().err
    with patch.object(sys, "argv", args), patch.dict(
        preflight.os.environ, {"INSPECTOR_SSH_TARGET": "stale@example"}
    ), patch.object(preflight, "run") as run:
        assert preflight.main() == 1
        run.assert_not_called()
    assert "Unset exported Compose" in capsys.readouterr().err
    with patch.object(sys, "argv", [*args[:4], "latest", *args[5:]]), patch.object(
        preflight, "validate_revisions"
    ), patch.object(
        preflight, "run"
    ) as run:
        assert preflight.main() == 1
        run.assert_not_called()
    assert "full sha256" in capsys.readouterr().err
    with patch.object(sys, "argv", ["release_preflight.py", "--help"]):
        with pytest.raises(SystemExit) as exited:
            runpy.run_path(str(SCRIPT), run_name="__main__")
    assert exited.value.code == 0
