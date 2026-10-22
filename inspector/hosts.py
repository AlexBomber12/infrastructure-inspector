"""Operator-owned, bounded SSH host registry."""

import json
import ipaddress
import os
import re
from dataclasses import dataclass
from pathlib import Path

CONFIG_PATH = Path("/run/secrets/host-registry.json")
SECRETS_DIR = Path("/run/secrets/inspector-hosts")
MAX_HOSTS = 8
MAX_CONFIG_BYTES = 8192
HOST_ID = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z", re.ASCII)
TARGET = re.compile(r"[a-z_][a-z0-9_-]{0,31}@[a-z0-9][a-z0-9.-]{0,252}\Z", re.ASCII)
LEGACY_TARGET = re.compile(r"(?:[a-z_][a-z0-9_-]{0,31}@)?[a-z0-9][a-z0-9.-]{0,252}\Z", re.ASCII)
IPV6_TARGET = re.compile(r"[a-z_][a-z0-9_-]{0,31}@\[([0-9a-fA-F:.]+)\]\Z", re.ASCII)
LEGACY_IPV6_TARGET = re.compile(r"(?:[a-z_][a-z0-9_-]{0,31}@)?\[([0-9a-fA-F:.]+)\]\Z", re.ASCII)
LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}\Z", re.ASCII)


@dataclass(frozen=True)
class Host:
    host_id: str
    label: str
    target: str
    key: str
    known_hosts: str


@dataclass(frozen=True)
class Registry:
    hosts: dict[str, Host]
    default_host: str

    def select(self, host_id):
        if host_id is None:
            host_id = self.default_host
        if not isinstance(host_id, str) or not HOST_ID.fullmatch(host_id) or host_id not in self.hosts:
            raise ValueError("Unknown host ID")
        return self.hosts[host_id]


def valid_target(value, *, legacy=False):
    if not isinstance(value, str):
        return False
    pattern = LEGACY_TARGET if legacy else TARGET
    if pattern.fullmatch(value) and ".." not in value:
        return True
    match = (LEGACY_IPV6_TARGET if legacy else IPV6_TARGET).fullmatch(value)
    if match is None:
        return False
    try:
        ipaddress.IPv6Address(match.group(1))
    except ValueError:
        return False
    return True


def _credential(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("Host credentials are missing or unsafe")
    return str(path)


def load_multi_registry(config_path=CONFIG_PATH, secrets_dir=SECRETS_DIR):
    """Load a fixed-schema file; IDs select deterministic credential paths."""
    if config_path.is_symlink() or not config_path.is_file() or config_path.stat().st_size > MAX_CONFIG_BYTES:
        raise ValueError("Host registry is missing or unsafe")
    try:
        with config_path.open(encoding="utf-8") as source:
            data = json.load(source, object_pairs_hook=_unique_pairs)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid host registry") from exc
    if not isinstance(data, dict) or set(data) != {"default_host", "hosts"}:
        raise ValueError("Invalid host registry schema")
    entries = data["hosts"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_HOSTS:
        raise ValueError("Invalid host count")
    hosts = {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"id", "label", "target"}:
            raise ValueError("Invalid host entry")
        host_id, label, target = entry["id"], entry["label"], entry["target"]
        if not isinstance(host_id, str) or not HOST_ID.fullmatch(host_id) or host_id in hosts:
            raise ValueError("Invalid or duplicate host ID")
        if not isinstance(label, str) or not LABEL.fullmatch(label):
            raise ValueError("Invalid host label")
        if not valid_target(target):
            raise ValueError("Invalid SSH target")
        directory = secrets_dir / host_id
        if directory.is_symlink():
            raise ValueError("Unsafe host credential directory")
        hosts[host_id] = Host(host_id, label, target.replace("[", "").replace("]", ""),
                              _credential(directory / "identity"),
                              _credential(directory / "known_hosts"))
    default = data["default_host"]
    if not isinstance(default, str) or default not in hosts:
        raise ValueError("Invalid default host")
    return Registry(hosts, default)


def _unique_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate registry field")
        value[key] = item
    return value


def legacy_registry(target, label, key, known_hosts):
    if target and not valid_target(target, legacy=True):
        raise ValueError("Invalid SSH target")
    return Registry({"default": Host("default", label, target.replace("[", "").replace("]", ""),
                                     key, known_hosts)}, "default")


def configured_registry():
    mode = os.environ.get("INSPECTOR_HOST_MODE", "legacy")
    if mode == "multi":
        return load_multi_registry()
    if mode != "legacy":
        raise ValueError("Invalid host mode")
    return None
