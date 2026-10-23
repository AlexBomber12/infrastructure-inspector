#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT
# Use only synthetic values; Compose interpolation must fail before any up.
cp .env.example "$tmp_dir/valid.env"
sed '/^INSPECTOR_SSH_TARGET=/d' "$tmp_dir/valid.env" > "$tmp_dir/missing.env"
if env -u INSPECTOR_SSH_TARGET docker compose --env-file "$tmp_dir/missing.env" -f compose.yaml config --quiet >/dev/null 2>&1; then
  echo 'Missing SSH target passed Compose interpolation' >&2
  exit 1
fi
sed 's/^INSPECTOR_SSH_TARGET=.*/INSPECTOR_SSH_TARGET=/' "$tmp_dir/valid.env" > "$tmp_dir/blank.env"
if env -u INSPECTOR_SSH_TARGET docker compose --env-file "$tmp_dir/blank.env" -f compose.yaml config --quiet >/dev/null 2>&1; then
  echo 'Blank SSH target passed Compose interpolation' >&2
  exit 1
fi
# A rollback image override must change only Inspector's image in the effective config.
cat > "$tmp_dir/rollback.yaml" <<'YAML'
services:
  inspector:
    image: sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
YAML
docker compose --env-file "$tmp_dir/valid.env" -f compose.yaml -p fixture-running-project config --format json > "$tmp_dir/before.json"
docker compose --env-file "$tmp_dir/valid.env" -f compose.yaml -f "$tmp_dir/rollback.yaml" -p fixture-running-project config --format json > "$tmp_dir/after.json"
python3 - "$tmp_dir/before.json" "$tmp_dir/after.json" <<'PY'
import json
import sys
before, after = (json.load(open(path, encoding="utf-8")) for path in sys.argv[1:])
assert before["name"] == after["name"] == "fixture-running-project"
assert before["services"]["inspector"]["image"] == "sha256:" + "a" * 64
assert after["services"]["inspector"]["image"] == "sha256:" + "b" * 64
after["services"]["inspector"]["image"] = before["services"]["inspector"]["image"]
assert after == before
PY
