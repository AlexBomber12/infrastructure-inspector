#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
bash scripts/unit-integration.sh
bash tests/test_restrictive_image_permissions.sh
bash scripts/e2e.sh
bash scripts/scan-secrets.sh
bash tests/test_secret_scan.sh
