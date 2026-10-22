#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
docker compose --env-file .env.example -f compose.yaml config --quiet
docker compose --env-file .env.multi.example -f compose.multi.yaml config --quiet
docker build -f inspector/Dockerfile -t infrastructure-inspector:ci inspector
docker build -f tests/Dockerfile -t infrastructure-inspector-test:ci .
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
  --tmpfs /tmp:rw,noexec,nosuid,size=32m \
  --env PYTHONPATH=/opt/ssh-inspector \
  --env COVERAGE_FILE=/tmp/.coverage \
  --entrypoint pytest \
  infrastructure-inspector-test:ci \
  -q -p no:cacheprovider /opt/tests/test_inspector.py /opt/tests/test_protocol.py \
  --cov=/opt/ssh-inspector --cov=/opt/host --cov-branch \
  --cov-report=term-missing --cov-fail-under=100
