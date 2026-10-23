#!/usr/bin/env bash
# Isolated network namespaces inside a disposable, networkless test container.
set -euo pipefail
policy=/opt/multi_network_policy.sh
private_ip=10.240.1.2
private_mac=02:42:ac:f0:01:02
private_gateway=10.240.1.1
egress_ip=10.240.2.2
egress_gateway=10.240.2.1
ai_ip=10.240.3.2
bridge=br-test-eg
ip link set lo up
if bash "$policy" render 999.240.1.2 "$private_mac" "$private_gateway" "$egress_ip" "$bridge" "$ai_ip" >/dev/null 2>&1; then
  echo 'Invalid policy address was accepted' >&2; exit 1
fi

for ns in inspector ai neighbor; do ip netns add "$ns"; done
trap 'for ns in inspector ai neighbor; do ip netns del "$ns" 2>/dev/null || true; done' EXIT
ip link add br-test-private type bridge
ip link add "$bridge" type bridge
ip link set br-test-private up
ip link set "$bridge" up
ip addr add "$private_gateway/24" dev br-test-private
ip addr add "$egress_gateway/24" dev "$bridge"
ip link add p-host type veth peer name p-client
ip link set p-host master br-test-private
ip link set p-host up
ip link set p-client netns inspector
ip netns exec inspector ip link set p-client address "$private_mac"
ip netns exec inspector ip link set p-client up
ip netns exec inspector ip addr add "$private_ip/24" dev p-client
ip link add e-host type veth peer name e-client
ip link set e-host master "$bridge"
ip link set e-host up
ip link set e-client netns inspector
ip netns exec inspector ip link set e-client up
ip netns exec inspector ip addr add "$egress_ip/24" dev e-client
ip netns exec inspector ip link set lo up
ip netns exec inspector ip route add default via "$egress_gateway"
ip link add wan-host type veth peer name wan-ai
ip addr add 10.240.3.1/24 dev wan-host
ip link set wan-host up
ip link set wan-ai netns ai
ip netns exec ai ip link set wan-ai up
ip netns exec ai ip addr add "$ai_ip/24" dev wan-ai
ip netns exec ai ip addr add 10.240.3.3/24 dev wan-ai
ip netns exec ai ip link set lo up
ip netns exec ai ip route add default via 10.240.3.1
ip link add n-host type veth peer name n-client
ip link set n-host master "$bridge"
ip link set n-host up
ip link set n-client netns neighbor
ip netns exec neighbor ip link set n-client up
ip netns exec neighbor ip addr add 10.240.2.3/24 dev n-client
ip netns exec neighbor ip link set lo up
echo 1 > /proc/sys/net/ipv4/ip_forward
if [[ ! -r /proc/sys/net/bridge/bridge-nf-call-iptables ]] ||
   [[ $(cat /proc/sys/net/bridge/bridge-nf-call-iptables) != 1 ]]; then
  echo 'Packet tests require br_netfilter with bridge-nf-call-iptables=1' >&2
  exit 1
fi

nc -l -p 22 -s "$private_gateway" >/dev/null & host_server=$!
nc -l -p 2222 -s "$private_gateway" >/dev/null & host_alt_server=$!
ip netns exec ai nc -l -p 22 -s "$ai_ip" >/dev/null & ai_server=$!
ip netns exec ai nc -l -p 22 -s 10.240.3.3 >/dev/null & bad_server=$!
ip netns exec ai nc -l -p 2222 -s "$ai_ip" >/dev/null & bad_port=$!
ip netns exec neighbor nc -l -p 22 -s 10.240.2.3 >/dev/null & neighbor_server=$!
trap 'kill "$host_server" "$host_alt_server" "$ai_server" "$bad_server" "$bad_port" "$neighbor_server" 2>/dev/null || true; for ns in inspector ai neighbor; do ip netns del "$ns" 2>/dev/null || true; done' EXIT

bash "$policy" install "$private_ip" "$private_mac" "$private_gateway" "$egress_ip" "$bridge" "$ai_ip"
bash "$policy" verify "$private_ip" "$private_mac" "$private_gateway" "$egress_ip" "$bridge" "$ai_ip"
nc -l -p 53 -s 127.0.0.254 >/dev/null & dns_tcp_server=$!
if nc -z -w 1 127.0.0.254 53; then
  echo 'Docker DNS sink accepted TCP traffic' >&2; exit 1
fi
python3 - <<'PY' &
import socket
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind(("127.0.0.254", 53))
server.settimeout(1)
try:
    server.recvfrom(128)
except socket.timeout:
    pass
else:
    with open("/tmp/dns-received", "w", encoding="utf-8") as output:
        output.write("yes")
PY
dns_udp_server=$!
sleep 0.1
python3 - <<'PY'
import socket
sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    sender.sendto(b"query", ("127.0.0.254", 53))
except PermissionError:
    pass
PY
wait "$dns_udp_server"
test ! -e /tmp/dns-received
allow() { ip netns exec inspector nc -z -w 1 "$1" "$2"; }
deny() { if allow "$1" "$2"; then echo "Unexpected access to $1:$2" >&2; exit 1; fi; }
deny_source() { if ip netns exec inspector nc -z -w 1 -s "$1" "$2" "$3"; then echo "Source-spoofed access to $2:$3" >&2; exit 1; fi; }
allow "$private_gateway" 22
allow "$ai_ip" 22
deny "$private_gateway" 2222
deny_source "$egress_ip" "$private_gateway" 2222
deny "$egress_gateway" 22
deny 10.240.3.1 22
deny 10.240.3.3 22
deny_source "$private_ip" 10.240.3.3 22
deny "$ai_ip" 2222
deny 10.240.2.3 22
bash "$policy" install "$private_ip" "$private_mac" "$private_gateway" "$egress_ip" "$bridge" "$ai_ip"
deny 10.240.3.3 22
# The dedicated bridge keeps its name when recreated; the same policy must
# continue to apply after its interface index changes.
ip link set e-host nomaster
ip link set n-host nomaster
ip link del "$bridge"
ip link add "$bridge" type bridge
ip link set "$bridge" up
ip addr add "$egress_gateway/24" dev "$bridge"
ip link set e-host master "$bridge"
ip link set n-host master "$bridge"
deny "$egress_gateway" 22
deny 10.240.2.3 22
deny 10.240.3.3 22
ip netns exec inspector ip route add 10.240.3.3/32 via "$private_gateway" dev p-client
deny 10.240.3.3 22
ip netns exec inspector ip route del 10.240.3.3/32
# Docker's ordinary MASQUERADE path should present the host-side address to
# the target. This synthetic NAT check catches source-address assumptions.
nft add table ip test_nat
nft 'add chain ip test_nat postrouting { type nat hook postrouting priority 100; policy accept; }'
nft add rule ip test_nat postrouting ip saddr "$egress_ip" ip daddr "$ai_ip" masquerade
ip netns exec ai python3 -c 'import socket; s=socket.socket(); s.bind(("10.240.3.2",22)); s.listen(1); c,a=s.accept(); open("/tmp/observed-source","w").write(a[0]); c.close()' & nat_server=$!
sleep 0.1
allow "$ai_ip" 22
wait "$nat_server"
test "$(cat /tmp/observed-source)" = 10.240.3.1
ip netns exec inspector ip -6 addr add fd42:240:2::2/64 dev e-client
ip -6 addr add fd42:240:2::1/64 dev "$bridge"
if ip netns exec inspector ping -6 -c 1 -W 1 fd42:240:2::1 >/dev/null 2>&1; then
  echo 'IPv6 host-local access was not rejected' >&2; exit 1
fi
ip netns exec inspector ip -6 addr add fd42:240:1::2/64 dev p-client
ip -6 addr add fd42:240:1::1/64 dev br-test-private
if ip netns exec inspector ping -6 -c 1 -W 1 fd42:240:1::1 >/dev/null 2>&1; then
  echo 'Private-interface IPv6 access was not rejected' >&2; exit 1
fi
bash "$policy" remove
bash "$policy" remove
nc -z -w 1 127.0.0.254 53
wait "$dns_tcp_server"
allow 10.240.3.3 22
echo 'Disposable packet allow, deny, IPv6 and rollback checks passed'
