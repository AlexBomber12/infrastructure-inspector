"""Docker integration for protected, synthetic release secret mounts.

Requires Docker access. Docker root is used only to create and clean fixtures.
"""

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
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
            try:
                sources[0].is_file()
            except PermissionError:
                pass
            else:
                raise AssertionError("original host-side PermissionError was not reproduced")
            preflight.validate_compose(config, copy.deepcopy(config),
                                       config["services"]["inspector"]["image"])
            preflight.validate_secrets(config, image)
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
        finally:
            fixture_change(directory, image, "cleanup")


if __name__ == "__main__":
    main()
