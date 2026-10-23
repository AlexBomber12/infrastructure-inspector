"""Docker integration for protected, synthetic release secret mounts.

Requires Docker access. Docker root is used only to create and clean fixtures.
"""

import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("release_preflight", ROOT / "scripts/release_preflight.py")
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


def fixture_change(directory, image, operation, name="key"):
    script = """import os, pathlib, sys
p = pathlib.Path('/fixture/secrets')
name = p / sys.argv[2]
if sys.argv[1] == 'setup':
    p.mkdir()
    for file, group in (('key', 65533), ('known', 65533), ('tunnel', 65532)):
        item = p / file
        item.write_text('synthetic fixture')
        os.chown(item, 0, group)
        item.chmod(0o440)
    os.chown(p, 0, 0)
    p.chmod(0o700)
elif sys.argv[1] == 'cleanup':
    if p.exists():
        p.chmod(0o700)
        for item in p.iterdir():
            item.rmdir() if item.is_dir() and not item.is_symlink() else item.unlink()
        p.rmdir()
elif sys.argv[1] == 'missing':
    name.unlink()
elif sys.argv[1] == 'empty':
    name.write_text('')
elif sys.argv[1] == 'directory':
    name.unlink()
    name.mkdir()
elif sys.argv[1] == 'symlink':
    name.unlink()
    name.symlink_to(p / 'known')
elif sys.argv[1] == 'inaccessible':
    name.chmod(0o400)
"""
    subprocess.run(["docker", "run", "--rm", "--network", "none", "--read-only",
                    "--user", "0:0",
                    "--mount", f"type=bind,src={directory},dst=/fixture",
                    "--entrypoint", "python", image, "-c", script,
                    operation, name], check=True, capture_output=True, text=True, timeout=30)


def main():
    image = subprocess.run(["docker", "image", "inspect", "infrastructure-inspector:ci",
                            "--format", "{{.Id}}"], check=True, capture_output=True,
                           text=True).stdout.strip()
    config = json.loads((ROOT / "tests/fixtures/compose-single-effective.json").read_text())
    with tempfile.TemporaryDirectory() as directory:
        Path(directory).chmod(0o755)
        try:
            fixture_change(directory, image, "setup")
            sources = [Path(directory) / "secrets" / name for name in ("key", "known", "tunnel")]
            mounts = [*config["services"]["inspector"]["volumes"],
                      *config["services"]["tunnel-client"]["volumes"]]
            for mount, source in zip(mounts, sources):
                mount["source"] = str(source)
            operator = ({"user": 65534, "group": 65534, "extra_groups": []}
                        if os.geteuid() == 0 else {})
            original = subprocess.run([
                sys.executable, "-c",
                "from pathlib import Path; import sys\n"
                "try: Path(sys.argv[1]).stat()\n"
                "except PermissionError: sys.exit(0)\n"
                "sys.exit(1)", str(sources[0])],
                capture_output=True, text=True, check=False, **operator)
            assert original.returncode == 0, "original host-side PermissionError was not reproduced"
            preflight.validate_compose(config, copy.deepcopy(config),
                                       config["services"]["inspector"]["image"])
            preflight.validate_secrets(config, image)
            try:
                preflight.secret_probe(
                    image, "65533:65533",
                    (f"type=bind,src={sources[0]},dst=/source-file,readonly",),
                    "import time; time.sleep(120)", (), "Synthetic timeout probe")
            except ValueError as exc:
                assert "probe timed out" in str(exc) and " removed" in str(exc)
                name = re.search(r"container (release-preflight-[0-9a-f]+) removed", str(exc))
                assert name is not None
                inspected = subprocess.run(
                    ["docker", "container", "inspect", name.group(1)],
                    capture_output=True, text=True, check=False, timeout=5)
                assert inspected.returncode != 0, "Timed-out probe container still exists"
            else:
                raise AssertionError("Synthetic Docker timeout probe unexpectedly finished")
            print("Protected Docker probe timeout cleanup passed")
            for name in ("key", "tunnel"):
                for case in ("missing", "empty", "directory", "symlink", "inaccessible"):
                    fixture_change(directory, image, case, name)
                    try:
                        preflight.validate_secrets(config, image)
                    except ValueError as exc:
                        assert "Required secret" in str(exc)
                    else:
                        raise AssertionError(f"{name}: {case} secret passed preflight")
                    fixture_change(directory, image, "cleanup")
                    fixture_change(directory, image, "setup")
            print("Protected secret mount integration passed: valid and ten invalid cases")
            test_multi_mounts(directory, image)
        finally:
            fixture_change(directory, image, "cleanup")


def test_multi_mounts(directory, image):
    config = json.loads((ROOT / "tests/fixtures/compose-multi-effective.json").read_text())
    registry = Path(directory) / "secrets" / "registry.json"
    hosts = Path(directory) / "secrets" / "hosts"
    script = """import os, pathlib, sys
p = pathlib.Path('/fixture/secrets')
registry = p / 'registry.json'
hosts = p / 'hosts'
mode = sys.argv[1]
if mode == 'setup':
    hosts.mkdir()
    for name in ('default', 'other'):
        child = hosts / name
        child.mkdir(mode=0o755)
        (child / 'identity').write_text('synthetic private key placeholder')
        os.chown(child / 'identity', 65533, 65533)
        (child / 'identity').chmod(0o600)
        (child / 'known_hosts').write_text('synthetic pinned host key placeholder')
        (child / 'known_hosts').chmod(0o644)
    registry.write_text('{"default_host":"default","hosts":[{"id":"default","label":"First","target":"audit@172.30.240.1"},{"id":"other","label":"Second","target":"audit@198.51.100.2"}]}')
    registry.chmod(0o644)
elif mode == 'missing':
    (hosts / 'other' / 'identity').unlink()
elif mode == 'wrong-default':
    registry.write_text(registry.read_text().replace('"default_host":"default"','"default_host":"other"'))
elif mode == 'bad-schema':
    registry.write_text('{"hosts":[]}')
elif mode == 'hostname':
    registry.write_text(registry.read_text().replace('198.51.100.2','host-b.example.invalid'))
elif mode == 'wrong-gateway':
    registry.write_text(registry.read_text().replace('172.30.240.1','172.30.240.2'))
elif mode == 'wrong-external':
    registry.write_text(registry.read_text().replace('198.51.100.2','172.30.241.3'))
elif mode == 'unreadable':
    os.chown(hosts / 'other' / 'identity', 0, 0)
    (hosts / 'other' / 'identity').chmod(0o400)
elif mode == 'permissive':
    (hosts / 'other' / 'identity').chmod(0o644)
elif mode == 'cleanup':
    for child in hosts.iterdir():
        for item in child.iterdir(): item.unlink()
        child.rmdir()
    hosts.rmdir()
    registry.unlink()
"""
    def change(mode):
        subprocess.run(["docker", "run", "--rm", "--network", "none", "--read-only",
                        "--user", "0:0", "--mount",
                        f"type=bind,src={directory},dst=/fixture", "--entrypoint",
                        "python", image, "-c", script, mode], check=True,
                       capture_output=True, text=True, timeout=30)
    mounts = config["services"]["inspector"]["volumes"]
    for mount in mounts:
        mount["source"] = str(registry if mount["target"].endswith(".json") else hosts)
    config["services"]["tunnel-client"]["volumes"][0]["source"] = str(Path(directory) / "secrets" / "tunnel")
    try:
        change("setup")
        preflight.validate_compose(config, copy.deepcopy(config),
                                   config["services"]["inspector"]["image"])
        preflight.validate_secrets(config, image)
        for mode in ("missing", "wrong-default", "bad-schema", "hostname",
                     "wrong-gateway", "wrong-external", "unreadable", "permissive"):
            change(mode)
            try:
                preflight.validate_secrets(config, image)
            except ValueError:
                pass
            else:
                raise AssertionError(f"multi-host {mode} passed release preflight")
            change("cleanup")
            change("setup")
        print("Protected multi-host registry and credential probes passed")
    finally:
        change("cleanup")


if __name__ == "__main__":
    main()
