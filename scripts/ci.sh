#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

docker compose --env-file .env.example -f compose.yaml config --quiet
docker build -f inspector/Dockerfile -t infrastructure-inspector:ci inspector
docker run --rm \
  --network none \
  --read-only \
  --user 65533:65533 \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --memory 256m \
  --pids-limit 64 \
  --mount "type=bind,src=$repo_root/tests,dst=/opt/tests,readonly" \
  --mount "type=bind,src=$repo_root/host,dst=/opt/host,readonly" \
  --entrypoint python \
  infrastructure-inspector:ci \
  -m unittest discover -s /opt/tests -v

bash scripts/scan-secrets.sh
bash tests/test_secret_scan.sh
