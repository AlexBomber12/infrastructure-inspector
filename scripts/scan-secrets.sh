#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
scan_root="${1:-$repo_root}"
scan_root="$(cd -- "$scan_root" && pwd)"

# A valid Git history with actual patch content is required. Gitleaks must never
# report success after a missing revision or an empty scan.
git -C "$scan_root" rev-parse --verify HEAD^{commit} >/dev/null
patch_bytes="$(git -C "$scan_root" log --all --full-history -p --format= | wc -c)"
if (( patch_bytes == 0 )); then
  echo "Secret scan refused an empty Git history" >&2
  exit 1
fi

image='ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f' # v8.30.1
scan_output="$(mktemp)"
trap 'rm -f "$scan_output"' EXIT

if docker run --rm --network none --read-only \
  --mount "type=bind,src=$scan_root,dst=/repo,readonly" \
  "$image" git --no-banner --no-color --redact /repo >"$scan_output" 2>&1 && \
  grep -Eq '[1-9][0-9]* commits scanned\.' "$scan_output" && \
  grep -Eq 'scanned ~[1-9][0-9]* bytes' "$scan_output"; then
  echo "Secret scan passed ($patch_bytes Git patch bytes checked)"
else
  # Gitleaks output may contain sensitive findings. Keep it out of public logs.
  echo "Secret scan failed; inspect locally with restricted output" >&2
  exit 1
fi
