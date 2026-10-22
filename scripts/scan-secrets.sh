#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
scan_root="${1:-$repo_root}"
scan_root="$(cd -- "$scan_root" && pwd)"

# A valid Git history with actual patch content is required. Gitleaks must never
# report success after a missing revision or an empty scan.
git -C "$scan_root" rev-parse --verify HEAD^{commit} >/dev/null
if [[ "$(git -C "$scan_root" rev-parse --is-shallow-repository)" == true ]]; then
  echo "Secret scan requires full Git history; this repository is shallow" >&2
  exit 1
fi
patch_bytes="$(git -C "$scan_root" log --all --full-history -m -p --text --no-textconv --no-ext-diff --format='%B' | wc -c)"
if (( patch_bytes == 0 )); then
  echo "Secret scan refused an empty Git history" >&2
  exit 1
fi

image='ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f' # v8.30.1
scratch="$(mktemp -d)"
scan_output="$scratch/output"
trap 'rm -r -- "$scratch"' EXIT

# Git runs on the host so linked worktrees can resolve external Git metadata.
# pipefail ensures a failed Git producer cannot produce a green stdin scan.
if ! git -C "$scan_root" log --all --full-history -m -p -U0 --text --no-textconv --no-ext-diff --format='%B' 2>/dev/null |
  tr '\000' '\n' |
  docker run --rm -i --network none --read-only \
    "$image" stdin --no-banner --no-color --redact >"$scan_output" 2>&1 ||
  ! grep -Eq 'scanned ~[1-9][0-9]* bytes' "$scan_output"; then
  # Gitleaks output may contain sensitive findings. Keep it out of public logs.
  echo "Git history secret scan failed; inspect locally with restricted output" >&2
  exit 1
fi

# The Git source preserves filenames for path-based detector rules. A local
# mirror also gives linked worktrees self-contained Git metadata in Docker.
git clone --mirror -q "$scan_root" "$scratch/mirror.git" 2>/dev/null
if ! docker run --rm --network none --read-only \
  --mount "type=bind,src=$scratch/mirror.git,dst=/repo,readonly" \
  "$image" git --no-banner --no-color --redact \
    --log-opts='--all --full-history -m --text --no-textconv --no-ext-diff' \
    /repo >"$scan_output" 2>&1 ||
  ! grep -Eq '[1-9][0-9]* commits scanned\.' "$scan_output"; then
  echo "Path-aware Git secret scan failed; inspect locally with restricted output" >&2
  exit 1
fi

# A staged file can differ from the working tree. Scan the index diff as well.
staged_bytes="$(git -C "$scan_root" diff --cached --no-ext-diff --text --no-color | wc -c)"
if ! git -C "$scan_root" diff --cached --no-ext-diff --text --no-color 2>/dev/null |
  tr '\000' '\n' |
  docker run --rm -i --network none --read-only \
    "$image" stdin --no-banner --no-color --redact >"$scan_output" 2>&1 ||
  { (( staged_bytes > 0 )) && ! grep -Eq 'scanned ~[1-9][0-9]* bytes' "$scan_output"; }; then
  echo "Staged secret scan failed; inspect locally with restricted output" >&2
  exit 1
fi

mkdir "$scratch/staged"
git -C "$scan_root" checkout-index --all --prefix="$scratch/staged/"
if ! docker run --rm --network none --read-only \
  --mount "type=bind,src=$scratch/staged,dst=/snapshot,readonly" \
  "$image" dir --no-banner --no-color --redact /snapshot >"$scan_output" 2>&1; then
  echo "Path-aware staged secret scan failed; inspect locally with restricted output" >&2
  exit 1
fi

# Read tracked and nonignored untracked working files. Ignored deployment
# credentials cannot be committed normally and must not break the local gate.
if ! git -C "$scan_root" ls-files -z --cached --others --exclude-standard |
  while IFS= read -r -d '' path; do
    file="$scan_root/$path"
    if [[ -f "$file" && ! -L "$file" ]]; then
      cat -- "$file"
      printf '\n'
    fi
  done |
  tr '\000' '\n' |
  docker run --rm -i --network none --read-only \
    "$image" stdin --no-banner --no-color --redact >"$scan_output" 2>&1 ||
  ! grep -Eq 'scanned ~[1-9][0-9]* bytes' "$scan_output"; then
  echo "Current-file secret scan failed; inspect locally with restricted output" >&2
  exit 1
fi

mkdir "$scratch/current"
git -C "$scan_root" ls-files -z --cached --others --exclude-standard |
  while IFS= read -r -d '' path; do
    file="$scan_root/$path"
    if [[ -f "$file" && ! -L "$file" ]]; then
      (cd "$scan_root" && cp --parents -- "$path" "$scratch/current")
    fi
  done
if ! docker run --rm --network none --read-only \
  --mount "type=bind,src=$scratch/current,dst=/snapshot,readonly" \
  "$image" dir --no-banner --no-color --redact /snapshot >"$scan_output" 2>&1; then
  echo "Path-aware current-file secret scan failed; inspect locally with restricted output" >&2
  exit 1
fi

echo "Secret scan passed ($patch_bytes Git patch bytes checked, path-aware history and pending files checked)"
