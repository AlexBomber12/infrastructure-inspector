#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
docker build --build-arg SOURCE_REVISION="$(git rev-parse HEAD)" -f inspector/Dockerfile -t infrastructure-inspector:ci inspector
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
ssh-keygen -q -t ed25519 -N '' -f "$fixture/key_b"
ssh-keygen -q -t ed25519 -N '' -f "$fixture/host_key_b"
ssh-keygen -q -t ed25519 -N '' -f "$fixture/wrong_host_key"
cp "$fixture/key.pub" "$fixture/authorized_keys"
awk '{print "sshd " $1 " " $2}' "$fixture/host_key.pub" > "$fixture/known_hosts"
awk '{print "sshd-b " $1 " " $2}' "$fixture/host_key_b.pub" > "$fixture/known_hosts_b"
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
sed -e 's@/run/fixture/host_key@/run/fixture/host_key_b@' \
    -e 's@/run/fixture/authorized_keys@/run/fixture/authorized_keys_b@' \
    "$fixture/sshd_config" > "$fixture/sshd_config_b"
cp "$fixture/key_b.pub" "$fixture/authorized_keys_b"
mkdir -p "$fixture/hosts/a" "$fixture/hosts/b"
cp "$fixture/key" "$fixture/hosts/a/identity"
cp "$fixture/known_hosts" "$fixture/hosts/a/known_hosts"
cp "$fixture/key_b" "$fixture/hosts/b/identity"
cp "$fixture/known_hosts_b" "$fixture/hosts/b/known_hosts"
cat > "$fixture/host-registry.json" <<'EOF'
{"default_host":"a","hosts":[{"id":"a","label":"e2e-host","target":"audit@sshd"},{"id":"b","label":"e2e-host-b","target":"audit@sshd-b"}]}
EOF
# Test credentials are confined to this disposable fixture. The Inspector user
# must own its private key and SSH must see mode 0600.
docker run --rm --network none --user 0:0 \
  --mount "type=bind,src=$fixture,dst=/fixture" \
  --entrypoint sh infrastructure-inspector:ci \
  -c 'chown 65533:65533 /fixture/key /fixture/key_b /fixture/wrong_key /fixture/hosts/a/identity /fixture/hosts/b/identity; chmod 600 /fixture/key /fixture/key_b /fixture/wrong_key /fixture/hosts/a/identity /fixture/hosts/b/identity'
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
  sshd-b:
    image: infrastructure-inspector-sshd:ci
    command: ["/usr/sbin/sshd", "-D", "-e", "-f", "/run/fixture/sshd_config_b"]
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
      INSPECTOR_HOST_MODE: multi
    volumes:
      - $fixture/host-registry.json:/run/secrets/host-registry.json:ro
      - $fixture/hosts:/run/secrets/inspector-hosts:ro
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
docker compose -p "$project" -f "$compose_file" up -d --build sshd sshd-b inspector
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
