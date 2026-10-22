#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
fixture_root="$(mktemp -d)"
trap 'rm -rf "$fixture_root"' EXIT

new_repo() {
  local path="$1"
  git init -q "$path"
  git -C "$path" config user.name 'CI fixture'
  git -C "$path" config user.email 'ci-fixture@example.invalid'
}

clean_repo="$fixture_root/clean"
new_repo "$clean_repo"
printf 'ordinary text\n' >"$clean_repo/example.txt"
git -C "$clean_repo" add example.txt
git -C "$clean_repo" commit -qm 'Clean root commit'
bash "$repo_root/scripts/scan-secrets.sh" "$clean_repo" >/dev/null

# The detector fixture is generated in a temporary repository, never committed
# to this public repository. Check the root commit and a later commit separately.
fixture_value='AKIAZ7X8Y9Q2W3E4R5T6'
for secret_position in root later; do
  secret_repo="$fixture_root/$secret_position"
  new_repo "$secret_repo"
  if [[ "$secret_position" == later ]]; then
    printf 'ordinary text\n' >"$secret_repo/example.txt"
    git -C "$secret_repo" add example.txt
    git -C "$secret_repo" commit -qm 'Clean root commit'
  fi
  printf 'access_key = %s\n' "$fixture_value" >"$secret_repo/example.txt"
  git -C "$secret_repo" add example.txt
  git -C "$secret_repo" commit -qm 'Synthetic detector fixture'
  if bash "$repo_root/scripts/scan-secrets.sh" "$secret_repo" >"$fixture_root/output" 2>&1; then
    echo "Secret scan missed a $secret_position commit fixture" >&2
    exit 1
  fi
  if grep -Fq "$fixture_value" "$fixture_root/output"; then
    echo 'Secret scan exposed a finding in its output' >&2
    exit 1
  fi
done

echo 'Secret scanner fixture checks passed'
