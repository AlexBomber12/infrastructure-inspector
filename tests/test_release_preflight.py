"""Hermetic validation of the operator's local release preflight."""

import importlib.util
from pathlib import Path
from unittest.mock import patch

import pytest
import server

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/release_preflight.py"
spec = importlib.util.spec_from_file_location("release_preflight", SCRIPT)
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


@pytest.fixture
def config(tmp_path):
    def mount(target):
        source = tmp_path / target.rsplit("/", 1)[-1]
        source.touch()
        return {"type": "bind", "source": str(source), "target": target,
                "read_only": True, "bind": {"create_host_path": False}}
    return {"services": {
        "inspector": {"image": preflight.IMAGE, "user": "65533:65533",
                      "read_only": True, "cap_drop": ["ALL"],
                      "security_opt": ["no-new-privileges:true"],
                      "environment": {"INSPECTOR_SSH_TARGET": "audit@fixture"},
                      "networks": {"mcp-private": None},
                      "volumes": [mount("/run/secrets/sg-audit-ed25519"),
                                  mount("/run/secrets/ssh-known-hosts")]},
        "tunnel-client": {"read_only": True,
                          "volumes": [mount("/run/secrets/control-plane-api-key")]},
    }, "networks": {"mcp-private": {"internal": True}}}


def test_source_version_and_revision_mismatch():
    source = Path(server.__file__).read_text()
    assert preflight.application_version(source) == "0.3.0"
    assert preflight.application_version(source.replace('version="0.3.0"',
                                                        'version="0.2.0"')) == "0.2.0"
    with pytest.raises(ValueError, match="literal MCP"):
        preflight.application_version("MCPServer('x', version=unknown)")
    with pytest.raises(ValueError, match="full commit"):
        preflight.validate_source("short")
    with patch.object(preflight, "run", return_value="a" * 40):
        with pytest.raises(ValueError, match="differs"):
            preflight.validate_source("b" * 40)


def test_single_host_compose_contract_and_invalid_release_config(config):
    preflight.validate_compose(config)
    inspector = config["services"]["inspector"]
    for field, value in (("image", "infrastructure-inspector:0.2.0"),
                         ("user", "0:0"), ("read_only", False),
                         ("privileged", True), ("ports", ["8000:8000"]),
                         ("cap_add", ["SYS_ADMIN"]), ("devices", ["/dev/sda"]),
                         ("pid", "host")):
        old = inspector.get(field)
        inspector[field] = value
        with pytest.raises(ValueError):
            preflight.validate_compose(config)
        if old is None:
            del inspector[field]
        else:
            inspector[field] = old
    inspector["environment"]["INSPECTOR_HOST_MODE"] = "multi"
    with pytest.raises(ValueError, match="multi-host"):
        preflight.validate_compose(config)
    del inspector["environment"]["INSPECTOR_HOST_MODE"]
    inspector["volumes"][0]["source"] = "/var/run/docker.sock"
    with pytest.raises(ValueError):
        preflight.validate_compose(config)


def test_secret_mount_must_exist_without_reading(config):
    source = Path(config["services"]["inspector"]["volumes"][0]["source"])
    source.unlink()
    with pytest.raises(ValueError, match="secret file missing"):
        preflight.validate_compose(config)


def test_image_identity_modules_and_ssh_restrictions():
    image_id = "sha256:" + "a" * 64
    revision = "b" * 40
    metadata = {"Id": image_id, "Config": {"User": "65533:65533", "Labels": {
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
        preflight.validate_image(metadata, image_id, probe)
        with pytest.raises(ValueError, match="image ID mismatch"):
            preflight.validate_image(metadata, "sha256:" + "c" * 64, probe)
        metadata["Config"]["Labels"]["org.opencontainers.image.version"] = "0.2.0"
        with pytest.raises(ValueError, match="version label"):
            preflight.validate_image(metadata, image_id, probe)
        metadata["Config"]["Labels"]["org.opencontainers.image.version"] = "0.3.0"
        probe["command"].remove("StrictHostKeyChecking=yes")
        with pytest.raises(ValueError, match="SSH client restrictions"):
            preflight.validate_image(metadata, image_id, probe)


def test_dispatcher_ordering_and_rollback_candidate(tmp_path):
    approved = preflight.ROOT / "host/sg-audit-dispatch.py"
    staged = tmp_path / "dispatcher.py"
    staged.write_bytes(approved.read_bytes())
    preflight.validate_dispatcher(staged)
    old = preflight.ROOT / "tests/fixtures/sg-audit-dispatch-020.py"
    staged.write_bytes(old.read_bytes())
    with pytest.raises(ValueError, match="differs"):
        preflight.validate_dispatcher(staged)
    staged.unlink()
    with pytest.raises(ValueError, match="missing"):
        preflight.validate_dispatcher(staged)
