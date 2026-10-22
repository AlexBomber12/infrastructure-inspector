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

git -C "$clean_repo" worktree add -q "$fixture_root/linked" HEAD
bash "$repo_root/scripts/scan-secrets.sh" "$fixture_root/linked" >/dev/null

printf 'another clean file\n' >"$clean_repo/second.txt"
git -C "$clean_repo" add second.txt
git -C "$clean_repo" commit -qm 'Second clean commit'
git clone -q --depth 1 "file://$clean_repo" "$fixture_root/shallow"
if bash "$repo_root/scripts/scan-secrets.sh" "$fixture_root/shallow" >"$fixture_root/output" 2>&1; then
  echo 'Secret scan accepted a shallow repository' >&2
  exit 1
fi
if ! grep -Fq 'shallow' "$fixture_root/output"; then
  echo 'Shallow repository failed for an unrelated reason' >&2
  exit 1
fi

# The detector fixture is generated in a temporary repository, never committed
# to this public repository. Check the root commit and a later commit separately.
fixture_value="$(printf '%s%s' 'AK' 'IAZ7X8Y9Q2W3E4R5T6')"
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

# A removed binary-classified blob exists only in history. Both NUL detection
# and a -diff attribute must still leave its contents visible to the scanner.
for binary_kind in nul attribute; do
  binary_repo="$fixture_root/binary-$binary_kind"
  new_repo "$binary_repo"
  if [[ "$binary_kind" == attribute ]]; then
    printf '*.dat -diff\n' >"$binary_repo/.gitattributes"
    git -C "$binary_repo" add .gitattributes
  fi
  printf 'ordinary text\n' >"$binary_repo/example.txt"
  git -C "$binary_repo" add example.txt
  git -C "$binary_repo" commit -qm 'Clean root commit'
  if [[ "$binary_kind" == nul ]]; then
    printf 'access_key = %s\000\n' "$fixture_value" >"$binary_repo/past.dat"
  else
    printf 'access_key = %s\n' "$fixture_value" >"$binary_repo/past.dat"
  fi
  git -C "$binary_repo" add past.dat
  git -C "$binary_repo" commit -qm 'Synthetic historical blob'
  git -C "$binary_repo" rm -q past.dat
  git -C "$binary_repo" commit -qm 'Remove synthetic blob'
  if bash "$repo_root/scripts/scan-secrets.sh" "$binary_repo" >"$fixture_root/output" 2>&1; then
    echo "Secret scan missed a removed $binary_kind blob" >&2
    exit 1
  fi
  if grep -Fq "$fixture_value" "$fixture_root/output"; then
    echo 'Secret scan exposed a historical finding in its output' >&2
    exit 1
  fi
done

printf 'access_key = %s\n' "$fixture_value" >"$clean_repo/pending.txt"
if bash "$repo_root/scripts/scan-secrets.sh" "$clean_repo" >"$fixture_root/output" 2>&1; then
  echo 'Secret scan missed an untracked secret fixture' >&2
  exit 1
fi
if grep -Fq "$fixture_value" "$fixture_root/output"; then
  echo 'Secret scan exposed a pending finding in its output' >&2
  exit 1
fi
rm "$clean_repo/pending.txt"

printf 'access_key = %s\n' "$fixture_value" >"$clean_repo/staged.txt"
git -C "$clean_repo" add staged.txt
printf 'ordinary text\n' >"$clean_repo/staged.txt"
if bash "$repo_root/scripts/scan-secrets.sh" "$clean_repo" >"$fixture_root/output" 2>&1; then
  echo 'Secret scan missed an index-only secret fixture' >&2
  exit 1
fi
git -C "$clean_repo" reset -q -- staged.txt
rm "$clean_repo/staged.txt"

printf 'secrets/\n' >"$clean_repo/.gitignore"
mkdir "$clean_repo/secrets"
printf 'access_key = %s\n' "$fixture_value" >"$clean_repo/secrets/local.txt"
bash "$repo_root/scripts/scan-secrets.sh" "$clean_repo" >/dev/null

# Reproduce a scanner that exits successfully after processing zero commits.
# The fake executable only supplies output; the real scanner was exercised above.
mkdir "$fixture_root/fake-bin"
cat >"$fixture_root/fake-bin/docker" <<'EOF'
#!/usr/bin/env bash
echo '0 commits scanned.'
echo 'scanned ~0 bytes (0)'
exit 0
EOF
chmod +x "$fixture_root/fake-bin/docker"
if PATH="$fixture_root/fake-bin:$PATH" \
  bash "$repo_root/scripts/scan-secrets.sh" "$clean_repo" >"$fixture_root/output" 2>&1; then
  echo 'Secret scan accepted a successful zero-commit result' >&2
  exit 1
fi

echo 'Secret scanner fixture checks passed'
