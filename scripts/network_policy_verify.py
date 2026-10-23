#!/usr/bin/env python3
"""Compare the complete installed Inspector nftables table with its reviewed policy."""

import ipaddress
import json
import re
import sys


def match(left, right, op="=="):
    return {"match": {"op": op, "left": left, "right": right}}


def field(protocol, name):
    return {"payload": {"protocol": protocol, "field": name}}


def interface(name):
    return match({"meta": {"key": "iifname"}}, name)


def rule(chain, expressions):
    return {"rule": {"family": "inet", "table": "inspector_multi",
                    "chain": chain, "expr": expressions}}


def expected_policy(private_ip, private_mac, private_gateway, egress_ip,
                    egress_bridge, destinations):
    name = "inspector_multi"
    table = {"table": {"family": "inet", "name": name}}
    chains = [{"chain": {"family": "inet", "table": name, "name": chain,
                         "type": "filter", "hook": chain, "prio": -100,
                         "policy": "accept"}} for chain in ("input", "forward", "output")]
    private = [interface("br-*"), match(field("ether", "saddr"), private_mac)]
    egress = [interface(egress_bridge)]
    established = match({"ct": {"key": "state"}}, ["established", "related"], "in")
    rules = [
        rule("output", [match(field("ip", "daddr"), "127.0.0.254"),
                        match(field("udp", "dport"), 53), {"drop": None}]),
        rule("output", [match(field("ip", "daddr"), "127.0.0.254"),
                        match(field("tcp", "dport"), 53), {"drop": None}]),
        rule("input", [*private, match(field("ip", "saddr"), private_ip),
                       match(field("ip", "daddr"), private_gateway),
                       match(field("tcp", "dport"), 22), {"accept": None}]),
        rule("input", [*private, {"drop": None}]),
        rule("input", [*egress, {"drop": None}]),
        rule("forward", [*private, established, {"accept": None}]),
        rule("forward", [*private, {"drop": None}]),
        rule("forward", [*egress, match(field("ip", "saddr"), egress_ip),
                         established, {"accept": None}]),
        *[rule("forward", [*egress, match(field("ip", "saddr"), egress_ip),
                            match(field("ip", "daddr"), destination),
                            match(field("tcp", "dport"), 22), {"accept": None}])
          for destination in destinations],
        rule("forward", [*egress, {"drop": None}]),
    ]
    return [table, *chains, *rules]


def normalize(value):
    """Ignore kernel handles and normalize equivalent literal representations."""
    if isinstance(value, dict):
        return {key: normalize(item) for key, item in value.items() if key != "handle"}
    if isinstance(value, list):
        return [normalize(item) for item in value]
    if isinstance(value, str):
        if re.fullmatch(r"[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}", value):
            return value.lower()
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return value
    return value


def verify_policy(actual, expected):
    entries = actual["nftables"]
    installed = [item for item in entries if "metainfo" not in item]
    # Nft lists chains in declaration order and rules in chain order. Restore
    # declaration order without changing the order of rules within each chain.
    tables = [item for item in installed if "table" in item]
    chains = [item for item in installed if "chain" in item]
    rules = [item for item in installed if "rule" in item]
    if len(installed) != len(tables) + len(chains) + len(rules):
        raise ValueError("unexpected objects in Inspector policy table")
    ordered_rules = [item for chain in ("output", "input", "forward")
                     for item in rules if item["rule"].get("chain") == chain]
    if normalize([*tables, *chains, *ordered_rules]) != normalize(expected):
        raise ValueError("installed Inspector policy differs from the reviewed rules; "
                         "stop Inspector and reinstall the policy before proceeding")


def main(argv):
    try:
        actual = json.load(sys.stdin)
        expected = expected_policy(argv[0], argv[1], argv[2], argv[3], argv[4], argv[5:])
        verify_policy(actual, expected)
    except (ValueError, KeyError, TypeError, IndexError, json.JSONDecodeError):
        print("Inspector network policy: installed policy is missing, invalid, or "
              "differs from the reviewed rules; stop Inspector and reinstall it",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
