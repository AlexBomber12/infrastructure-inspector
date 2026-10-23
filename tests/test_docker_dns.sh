#!/usr/bin/env bash
# Actual Docker embedded-resolver regression with synthetic, disposable peers.
set -euo pipefail
network="inspector-dns-$$"
peer="inspector-dns-peer-$$"
cleanup() {
  docker rm -f "$peer" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker network create "$network" >/dev/null
docker run -d --name "$peer" --network "$network" \
  --entrypoint python infrastructure-inspector:ci \
  -c 'import time; time.sleep(120)' >/dev/null
docker run --rm --network "$network" --dns 127.0.0.254 \
  --read-only --user 65533:65533 --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --entrypoint python infrastructure-inspector:ci -c '
import socket, sys
assert socket.getaddrinfo(sys.argv[1], 8000), "Docker peer lookup failed"
try:
    socket.getaddrinfo("example.com", 443)
except socket.gaierror:
    pass
else:
    raise AssertionError("Docker forwarded an external DNS query")
' "$peer"
echo 'Docker embedded DNS kept peer discovery and rejected external resolution'
