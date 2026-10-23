#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
fixture="$(mktemp -d)"
trap 'rm -rf -- "$fixture"' EXIT
context="$fixture/context"
mkdir -m 700 "$context"
cp inspector/Dockerfile inspector/requirements.lock inspector/server.py \
  inspector/catalog.py inspector/bounded.py inspector/hosts.py "$context/"
chmod 600 "$context"/*
revision="$(git rev-parse HEAD)"
probe="$(python3 -c 'import runpy; print(runpy.run_path("scripts/release_preflight.py")["PROBE"])')"

for builder in 0 1; do
  image="infrastructure-inspector:restrictive-permissions-$builder"
  DOCKER_BUILDKIT="$builder" docker build --build-arg SOURCE_REVISION="$revision" \
    -t "$image" "$context"
  docker image inspect "$image" > "$fixture/image.json"
  image_id="$(docker image inspect --format '{{.Id}}' "$image")"
  docker run --rm --network none --read-only --user 65533:65533 \
    --entrypoint python "$image_id" -c "$probe" > "$fixture/probe.json"
  python3 - "$fixture/image.json" "$fixture/probe.json" "$image_id" <<'PY'
import json
from pathlib import Path
import runpy
import sys

preflight = runpy.run_path("scripts/release_preflight.py")
metadata = json.loads(Path(sys.argv[1]).read_text())[0]
probe = json.loads(Path(sys.argv[2]).read_text())
preflight["validate_image"](metadata, sys.argv[3], probe)
assert probe["modules"] == [
    f"/opt/ssh-inspector/{name}.py"
    for name in ("server", "catalog", "bounded", "hosts")
]
PY
  docker run --rm --network none --read-only --user 65533:65533 \
    --entrypoint python "$image_id" -c '
import os
from pathlib import Path
import stat

root = Path("/opt/ssh-inspector")
assert set(os.listdir(root)) == {
    "requirements.lock", "server.py", "catalog.py", "bounded.py", "hosts.py"
}
for directory in (Path("/opt"), root):
    info = directory.stat()
    assert info.st_uid == 0 and info.st_gid == 0
    assert stat.S_IMODE(info.st_mode) == 0o755
for name in ("server", "catalog", "bounded", "hosts"):
    path = root / f"{name}.py"
    info = path.stat()
    assert info.st_uid == 0 and info.st_gid == 0
    assert stat.S_IMODE(info.st_mode) == 0o644
    assert not os.access(path, os.W_OK)
for secret in ("sg-audit-ed25519", "ssh-known-hosts", "control-plane-api-key"):
    assert not (Path("/run/secrets") / secret).exists()
'
done
