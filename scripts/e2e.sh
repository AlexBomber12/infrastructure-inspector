#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
docker build -f inspector/Dockerfile -t infrastructure-inspector:ci inspector
docker build -f tests/Dockerfile -t infrastructure-inspector-test:ci .
fixture="$(mktemp -d)"
chmod 755 "$fixture"
project="inspector-e2e-$$"
compose_file="$fixture/compose.yaml"
cleanup() {
  result=$?
  if (( result != 0 )); then
    docker compose -p "$project" -f "$compose_file" logs --no-color --tail=80 >&2 || true
  fi
  docker compose -p "$project" -f "$compose_file" down --volumes --remove-orphans >/dev/null 2>&1 || true
  rm -rf -- "$fixture"
}
trap cleanup EXIT
ssh-keygen -q -t ed25519 -N '' -f "$fixture/key"
ssh-keygen -q -t ed25519 -N '' -f "$fixture/wrong_key"
ssh-keygen -q -t ed25519 -N '' -f "$fixture/host_key"
ssh-keygen -q -t ed25519 -N '' -f "$fixture/wrong_host_key"
cp "$fixture/key.pub" "$fixture/authorized_keys"
awk '{print "sshd " $1 " " $2}' "$fixture/host_key.pub" > "$fixture/known_hosts"
awk '{print "sshd " $1 " " $2}' "$fixture/wrong_host_key.pub" > "$fixture/wrong_known_hosts"
cat > "$fixture/sshd_config" <<'EOF'
Port 22
ListenAddress 0.0.0.0
HostKey /run/fixture/host_key
AuthorizedKeysFile /run/fixture/authorized_keys
StrictModes no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AllowUsers audit
ForceCommand /usr/local/bin/python3 /opt/host/sg-audit-dispatch.py
PidFile /run/sshd/sshd.pid
AllowTcpForwarding no
X11Forwarding no
PermitTTY no
LogLevel ERROR
EOF
# Test credentials are confined to this disposable fixture. The Inspector user
# must own its private key and SSH must see mode 0600.
docker run --rm --network none --user 0:0 \
  --mount "type=bind,src=$fixture,dst=/fixture" \
  --entrypoint sh infrastructure-inspector:ci \
  -c 'chown 65533:65533 /fixture/key /fixture/wrong_key; chmod 600 /fixture/key /fixture/wrong_key'
cat > "$compose_file" <<EOF
name: $project
services:
  sshd:
    build:
      context: $repo_root
      dockerfile: tests/sshd.Dockerfile
    image: infrastructure-inspector-sshd:ci
    read_only: true
    volumes:
      - $fixture:/run/fixture:ro
    tmpfs:
      - /run/sshd
    networks: [isolated]
  inspector:
    image: infrastructure-inspector:ci
    user: "65533:65533"
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    pids_limit: 64
    environment:
      INSPECTOR_SSH_TARGET: audit@sshd
      INSPECTOR_HOST_LABEL: e2e-host
    volumes:
      - $fixture/key:/run/secrets/sg-audit-ed25519:ro
      - $fixture/known_hosts:/run/secrets/ssh-known-hosts:ro
    tmpfs:
      - /tmp
    networks: [isolated]
  client:
    image: infrastructure-inspector-test:ci
    user: "65533:65533"
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    volumes:
      - $repo_root/tests:/opt/tests:ro
      - $fixture:/run/fixture:ro
    tmpfs:
      - /tmp
    networks: [isolated]
networks:
  isolated:
    internal: true
EOF
docker compose -p "$project" -f "$compose_file" up -d --build sshd inspector
# Poll from the isolated client; failure to become ready is fatal.
ready=0
for attempt in $(seq 1 30); do
  if docker compose -p "$project" -f "$compose_file" run --rm -T client \
      python -c 'import socket;socket.create_connection(("inspector",8000),2)' >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if (( ready == 0 )); then
  docker compose -p "$project" -f "$compose_file" logs --no-color --tail=100 >&2
  echo 'Inspector failed to start' >&2
  exit 1
fi
docker compose -p "$project" -f "$compose_file" run --rm -T client \
  pytest -q -p no:cacheprovider /opt/tests/test_e2e_client.py -k 'not unavailable_ssh_server'
docker compose -p "$project" -f "$compose_file" stop sshd
docker compose -p "$project" -f "$compose_file" run --rm -T client \
  pytest -q -p no:cacheprovider /opt/tests/test_e2e_client.py -k unavailable_ssh_server
