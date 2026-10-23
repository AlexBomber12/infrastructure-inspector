#!/usr/bin/env bash
# Render, install, verify or remove only the Inspector-owned nftables table.
# All addresses are operator-supplied; this script never contacts an SSH host.
set -euo pipefail

fail() { echo "Inspector network policy: $*" >&2; exit 1; }

mode=${1:-}
if [[ $mode == remove ]]; then
  [[ $# == 1 ]] || fail 'remove takes no address arguments'
  if nft list table inet inspector_multi >/dev/null 2>&1; then
    nft delete table inet inspector_multi
  fi
  exit
fi
[[ $mode == render || $mode == install || $mode == verify ]] || fail 'expected render, install, verify, or remove'
[[ $# -ge 7 ]] || fail 'expected PRIVATE_IP PRIVATE_MAC PRIVATE_GATEWAY EGRESS_IP EGRESS_BRIDGE EXTERNAL_IP...'
shift
private_ip=$1 private_mac=$2 private_gateway=$3 egress_ip=$4 egress_bridge=$5
shift 5
[[ $private_mac =~ ^02(:[0-9a-fA-F]{2}){5}$ ]] || fail 'invalid private MAC'
[[ $egress_bridge =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || fail 'invalid egress bridge name'
for address in "$private_ip" "$private_gateway" "$egress_ip" "$@"; do
  [[ $address =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || fail 'only literal IPv4 addresses are allowed'
  IFS=. read -r -a octets <<< "$address"
  for octet in "${octets[@]}"; do
    (( 10#$octet <= 255 )) || fail 'invalid IPv4 address'
  done
done
(( $# <= 7 )) || fail 'too many external hosts'

render() {
  cat <<EOF
add table inet inspector_multi
add chain inet inspector_multi input { type filter hook input priority -100; policy accept; }
add chain inet inspector_multi forward { type filter hook forward priority -100; policy accept; }
add chain inet inspector_multi output { type filter hook output priority -100; policy accept; }
add rule inet inspector_multi output ip daddr 127.0.0.254 udp dport 53 drop
add rule inet inspector_multi output ip daddr 127.0.0.254 tcp dport 53 drop
add rule inet inspector_multi input iifname "br-*" ether saddr $private_mac ip saddr $private_ip ip daddr $private_gateway tcp dport 22 accept
add rule inet inspector_multi input iifname "br-*" ether saddr $private_mac drop
add rule inet inspector_multi input iifname "$egress_bridge" drop
add rule inet inspector_multi forward iifname "br-*" ether saddr $private_mac ct state established,related accept
add rule inet inspector_multi forward iifname "br-*" ether saddr $private_mac drop
add rule inet inspector_multi forward iifname "$egress_bridge" ip saddr $egress_ip ct state established,related accept
EOF
  for address in "$@"; do
    printf 'add rule inet inspector_multi forward iifname "%s" ip saddr %s ip daddr %s tcp dport 22 accept\n' \
      "$egress_bridge" "$egress_ip" "$address"
  done
  cat <<EOF
add rule inet inspector_multi forward iifname "$egress_bridge" drop
EOF
}

if [[ $mode == render ]]; then
  render "$@"
  exit
fi

command -v nft >/dev/null || fail 'nft is required'
[[ -r /proc/sys/net/bridge/bridge-nf-call-iptables ]] &&
  [[ $(cat /proc/sys/net/bridge/bridge-nf-call-iptables) == 1 ]] ||
  fail 'br_netfilter with bridge-nf-call-iptables=1 is required'
if [[ $mode == verify ]]; then
  nft list table inet inspector_multi >/dev/null || fail 'policy table is missing'
  exit
fi

policy=$(mktemp)
trap 'rm -f -- "$policy"' EXIT
if nft list table inet inspector_multi >/dev/null 2>&1; then
  echo 'delete table inet inspector_multi' > "$policy"
fi
render "$@" >> "$policy"
nft -c -f "$policy" || fail 'policy failed validation'
nft -f "$policy" || fail 'policy installation failed'
