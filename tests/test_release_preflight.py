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


def test_secret_probe_timeout_removes_only_its_disposable_container(config):
    image_id = config["services"]["inspector"]["image"]
    timeout = preflight.subprocess.TimeoutExpired("docker", 30)
    with patch.object(preflight.subprocess, "run", side_effect=[
        timeout, SimpleNamespace(returncode=0)]) as run:
        with pytest.raises(ValueError, match="probe timed out"):
            preflight.validate_secrets(config, image_id)
        assert run.call_args_list[1].args[0][:4] == (
            "docker", "container", "rm", "--force")
        assert run.call_args_list[1].args[0][4] == run.call_args_list[0].args[0][4]
    with patch.object(preflight.subprocess, "run", side_effect=[timeout, OSError()]):
        with pytest.raises(ValueError, match="probe timed out"):
            preflight.validate_secrets(config, image_id)


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
