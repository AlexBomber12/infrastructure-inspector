"""Host-side allowlist authorization uses Inspector's mounted registry."""

import importlib.util
import json
from pathlib import Path
import runpy
import sys
from unittest.mock import patch

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/multi_host_allowlist.py"
spec = importlib.util.spec_from_file_location("multi_host_allowlist", SCRIPT)
allowlist = importlib.util.module_from_spec(spec)
spec.loader.exec_module(allowlist)


@pytest.fixture
def deployment(tmp_path):
    source = tmp_path / "registry.json"
    secrets = tmp_path / "hosts"
    for host_id in ("default", "ai-server", "third"):
        folder = secrets / host_id
        folder.mkdir(parents=True)
        (folder / "identity").write_text("disposable identity")
        (folder / "known_hosts").write_text("disposable host key")
    data = {"default_host": "default", "hosts": [
        {"id": "default", "label": "Server", "target": "audit@10.253.252.1"},
        {"id": "ai-server", "label": "AI Server", "target": "audit@192.0.2.10"},
        {"id": "third", "label": "Third", "target": "audit@192.0.2.11"},
    ]}
    source.write_text(json.dumps(data))
    return source, secrets, data


def arguments(deployment, external=("192.0.2.11", "192.0.2.10")):
    source, secrets, _ = deployment
    return str(source), str(secrets), "10.253.252.1", "10.253.252.0/24", "10.253.253.0/24", external


def test_exact_set_and_cli_success(deployment):
    assert allowlist.validate(*arguments(deployment)) is None
    assert allowlist.main([*arguments(deployment)[:5], *arguments(deployment)[5]]) == 0


@pytest.mark.parametrize("external", [
    ("192.0.2.10",),
    ("192.0.2.10", "192.0.2.12"),
    ("192.0.2.10", "192.0.2.11", "192.0.2.12"),
    ("192.0.2.10", "192.0.2.10"),
    ("192.0.2.10", "10.253.252.1"),
    ("192.0.2.10", "example.com"),
    ("192.0.2.10", "2001:db8::1"),
    ("192.0.2.10", "192.0.2.999"),
])
def test_rejects_invalid_allowlist(deployment, external):
    with pytest.raises(ValueError):
        allowlist.validate(*arguments(deployment, external))


@pytest.mark.parametrize("target", [
    "audit@example.com", "audit@2001:db8::1", "audit@192.0.2.999",
    "audit@10.253.252.2", "audit@10.253.253.2",
])
def test_rejects_invalid_external_registry_target(deployment, target):
    source, _, data = deployment
    data["hosts"][1]["target"] = target
    source.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        allowlist.validate(*arguments(deployment))


def test_rejects_registry_structure_and_default(deployment):
    source, _, data = deployment
    data["hosts"][2]["target"] = "audit@192.0.2.10"
    source.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="external host"):
        allowlist.validate(*arguments(deployment))
    data["hosts"] = data["hosts"][:1]
    source.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="external host"):
        allowlist.validate(*arguments(deployment))
    data["default_host"] = "default"
    data["hosts"][0]["target"] = "audit@10.253.252.2"
    source.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="private gateway"):
        allowlist.validate(*arguments(deployment))
    data["default_host"] = "ai-server"
    data["hosts"].append({"id": "ai-server", "label": "AI Server", "target": "audit@192.0.2.10"})
    source.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="default host"):
        allowlist.validate(*arguments(deployment))


def test_rejects_invalid_gateway_and_paths(deployment, tmp_path):
    args = arguments(deployment)
    with pytest.raises(ValueError, match="private gateway"):
        allowlist.validate(args[0], args[1], "10.253.251.1", *args[3:])
    with pytest.raises(ValueError, match="mounted registry"):
        allowlist.validate("registry.json", *args[1:])
    with pytest.raises(ValueError, match="mounted registry"):
        allowlist.validate(args[0], "hosts", *args[2:])
    link = tmp_path / "linked.json"
    link.symlink_to(deployment[0])
    with pytest.raises(ValueError, match="mounted registry"):
        allowlist.validate(str(link), *args[1:])


def test_rejects_registry_permissions_and_sanitizes_errors(deployment, capsys):
    source = deployment[0]
    source.chmod(0o666)
    with pytest.raises(ValueError, match="permissions"):
        allowlist.validate(*arguments(deployment))
    source.chmod(0o000)
    with pytest.raises(ValueError, match="permissions"):
        allowlist.validate(*arguments(deployment))
    source.chmod(0o644)
    source.write_text("{SENSITIVE_REGISTRY_BYTES")
    assert allowlist.main([*arguments(deployment)[:5], *arguments(deployment)[5]]) == 1
    error = capsys.readouterr().err
    assert "SENSITIVE_REGISTRY_BYTES" not in error
    assert "invalid or differ" in error
    assert allowlist.main([]) == 1
    source.unlink()
    assert allowlist.main([*arguments(deployment)[:5], *arguments(deployment)[5]]) == 1


def test_script_entrypoint(deployment):
    args = [str(SCRIPT), *arguments(deployment)[:5], *arguments(deployment)[5]]
    with patch.object(sys, "argv", args), pytest.raises(SystemExit) as exc:
        runpy.run_path(str(SCRIPT), run_name="__main__")
    assert exc.value.code == 0
