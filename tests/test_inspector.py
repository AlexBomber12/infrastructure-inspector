import asyncio
import importlib.util
import io
import json
import os
import runpy
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

import server
from bounded import Captured, run_bounded
from catalog import CHECKS, LEGACY_OPERATIONS
from hosts import Host, Registry, load_multi_registry, legacy_registry, configured_registry

DISPATCHER_PATH = Path(__file__).resolve().parents[1] / "host" / "sg-audit-dispatch.py"
spec = importlib.util.spec_from_file_location("dispatcher", DISPATCHER_PATH)
dispatcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dispatcher)

EXPECTED_COMMANDS = {
    "system.identity": ["/usr/bin/id"],
    "system.uptime": ["/usr/bin/uptime"],
    "network.listeners": ["/usr/bin/ss", "-H", "-lnt"],
    "system.services": [
        "/usr/bin/systemctl", "list-units", "--type=service",
        "--state=running", "--no-pager", "--plain", "--no-legend",
    ],
    "system.os": ["/usr/bin/cat", "/etc/os-release"],
    "system.kernel": ["/usr/bin/uname", "-srmo"],
    "system.cpu": ["/usr/bin/lscpu"],
    "system.memory": ["/usr/bin/free", "-b"],
    "system.block_devices": [
        "/usr/bin/lsblk", "--json", "--bytes", "-o",
        "NAME,KNAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS,MODEL,TRAN",
    ],
    "system.filesystems": ["/usr/bin/df", "-P", "-B1", "-T"],
    "system.mounts": ["/usr/bin/findmnt", "--json", "-o", "TARGET,SOURCE,FSTYPE"],
    "system.processes": ["/usr/bin/ps", "-eo", "pid,ppid,user,stat,comm", "--sort=pid"],
    "network.interfaces": ["/usr/sbin/ip", "-j", "address", "show"],
    "network.routes_ipv4": ["/usr/sbin/ip", "-j", "-4", "route", "show"],
    "network.routes_ipv6": ["/usr/sbin/ip", "-j", "-6", "route", "show"],
}


class HostRegistryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / "registry.json"
        self.secrets = self.root / "hosts"
        self.data = {"default_host": "a", "hosts": [
            {"id": "a", "label": "Host A", "target": "audit@host-a"},
            {"id": "b", "label": "Host B", "target": "audit@host-b"},
        ]}
        for host_id in ("a", "b"):
            directory = self.secrets / host_id
            directory.mkdir(parents=True)
            (directory / "identity").write_text("fixture")
            (directory / "known_hosts").write_text("fixture")

    def load(self):
        self.config.write_text(json.dumps(self.data))
        return load_multi_registry(self.config, self.secrets)

    def test_valid_registry_routing_and_legacy(self):
        registry = self.load()
        self.assertEqual(registry.select(None).target, "audit@host-a")
        self.assertEqual(registry.select("b").key, str(self.secrets / "b" / "identity"))
        with patch.object(server, "MULTI_REGISTRY", registry), patch.object(
            server, "run_bounded", return_value=Captured(0, b"ok", b"", False)
        ) as run:
            self.assertEqual(server.list_hosts(), [
                {"host_id": "a", "label": "Host A"},
                {"host_id": "b", "label": "Host B"},
            ])
            self.assertEqual(server.inspect("system.os")["host_id"], "a")
            self.assertEqual(server.inspect("system.os", "b")["host_id"], "b")
            self.assertEqual(run.call_args.args[0], [
                "/usr/bin/ssh", "-F", "/dev/null", "-T", "-i",
                str(self.secrets / "b" / "identity"),
                "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
                "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                "-o", "UserKnownHostsFile=" + str(self.secrets / "b" / "known_hosts"),
                "-o", "GlobalKnownHostsFile=/dev/null", "-o", "UpdateHostKeys=no",
                "-o", "ConnectTimeout=5", "-o", "ConnectionAttempts=1",
                "-o", "ClearAllForwardings=yes", "-o", "HostKeyAlgorithms=ssh-ed25519",
                "audit@host-b", "system.os",
            ])
            self.assertEqual(server.inspect_batch(["system.os"], "b")[0]["host_id"], "b")
            self.assertEqual(server.inspect_server("identity")["host"], "Host A")
            for bad in ("unknown", "-oProxyCommand=id", 2, {}, "a; id"):
                with self.assertRaises(ValueError):
                    server.inspect("system.os", bad)
            for bad in ("unknown", "a; id"):
                with self.assertRaises(ValueError):
                    server.inspect_batch(["system.os"], bad)
            self.assertEqual(run.call_count, 4)
        legacy = legacy_registry("audit@host-a", "Legacy", "key", "hosts")
        self.assertEqual(legacy.select(None).host_id, "default")
        self.assertEqual(legacy.select(None).label, "Legacy")
        self.assertEqual(legacy_registry("audit@[2001:db8::10]", "IPv6", "key", "hosts")
                         .select(None).target, "audit@2001:db8::10")
        self.assertEqual(legacy_registry("[2001:db8::10]", "IPv6", "key", "hosts")
                         .select(None).target, "2001:db8::10")
        with patch.object(server, "MULTI_REGISTRY", None), patch.object(
            server, "SSH_TARGET", "audit@[2001:db8::10]"
        ), patch.object(server, "run_bounded", return_value=Captured(0, b"ok", b"", False)) as run:
            self.assertEqual(server.inspect("system.os")["status"], "success")
            self.assertEqual(run.call_args.args[0][-2:], ["audit@2001:db8::10", "system.os"])
        for uri in ("ssh://audit@example.com:2222", "ssh://example.com",
                    "ssh://audit@Server.Example.COM:2222", "audit@Server.Example.COM"):
            with self.subTest(uri=uri), patch.object(server, "MULTI_REGISTRY", None), patch.object(
                server, "SSH_TARGET", uri
            ), patch.object(server, "run_bounded", return_value=Captured(0, b"ok", b"", False)) as run:
                self.assertEqual(server.inspect("system.os")["status"], "success")
                self.assertEqual(run.call_args.args[0][-2:], [uri, "system.os"])
                parsed = subprocess.run(
                    ["/usr/bin/ssh", "-G", "-F", "/dev/null", uri],
                    capture_output=True, check=False,
                )
                self.assertEqual(parsed.returncode, 0, parsed.stderr)
        rejected_uri = "ssh://audit@[2001:db8::10]:2222"
        self.assertNotEqual(subprocess.run(
            ["/usr/bin/ssh", "-G", "-F", "/dev/null", rejected_uri],
            capture_output=True, check=False,
        ).returncode, 0)
        self.data["hosts"][1]["target"] = "audit@[2001:db8::10]"
        self.assertEqual(self.load().select("b").target, "audit@2001:db8::10")
        with patch.object(server, "MULTI_REGISTRY", None), patch.object(server, "SSH_TARGET", "audit@host-a"):
            self.assertEqual(server.list_hosts(), [{"host_id": "default", "label": server.HOST_LABEL}])
        for target in ("-oProxyCommand=id", "audit@host..a", "audit@host;id",
                       "audit@[invalid]", "audit@[1234]", 42,
                       "ssh://audit@host..a:22", "ssh://audit@example.com:0",
                       "ssh://audit@example.com:65536", "ssh://audit@example.com:2222/id",
                       "ssh://audit@[1234]:2222", rejected_uri,
                       "ssh://-oProxyCommand=id@host"):
            with self.assertRaises(ValueError):
                legacy_registry(target, "Legacy", "key", "hosts")

    def test_invalid_registry_fields_and_limits(self):
        self.load()
        changes = [
            {"default_host": "missing"}, {"hosts": []},
            {"hosts": self.data["hosts"] * 5},
            {"hosts": [self.data["hosts"][0]] * 2},
            {"hosts": [{"id": "-bad", "label": "Host", "target": "audit@host"}]},
            {"hosts": [{"id": "a", "label": "!", "target": "audit@host"}]},
            {"hosts": [{"id": "a", "label": "Host", "target": "-oProxyCommand=id"}]},
            {"hosts": [{"id": "a", "label": "Host", "target": "audit@host..a"}]},
            {"hosts": [{"id": "a", "label": "Host", "target": "audit@[1234]"}]},
            {"hosts": [{"id": "a", "label": "Host", "target": 42}]},
            {"hosts": [{"id": "a", "label": "Host"}]},
            {"hosts": "wrong"}, {"hosts": [1]},
        ]
        for change in changes:
            with self.subTest(change=change):
                self.data = {"default_host": "a", "hosts": [
                    {"id": "a", "label": "Host A", "target": "audit@host-a"},
                    {"id": "b", "label": "Host B", "target": "audit@host-b"},
                ]} | change
                with self.assertRaises(ValueError):
                    self.load()
        for raw in ('{"default_host":"a","default_host":"b","hosts":[]}',
                    "{bad", '[]', '{"hosts":[]}'):
            with self.subTest(raw=raw):
                self.config.write_text(raw)
                with self.assertRaises(ValueError):
                    load_multi_registry(self.config, self.secrets)
        self.config.write_text("x" * 8193)
        with self.assertRaises(ValueError):
            load_multi_registry(self.config, self.secrets)
        self.config.unlink()
        with self.assertRaises(ValueError):
            load_multi_registry(self.config, self.secrets)
        self.config.symlink_to(self.root / "other")
        with self.assertRaises(ValueError):
            load_multi_registry(self.config, self.secrets)

    def test_missing_and_unsafe_credentials_and_modes(self):
        self.load()
        (self.secrets / "b" / "identity").unlink()
        with self.assertRaises(ValueError):
            self.load()
        (self.secrets / "b" / "identity").symlink_to(self.secrets / "a" / "identity")
        with self.assertRaises(ValueError):
            self.load()
        (self.secrets / "b" / "identity").unlink()
        (self.secrets / "b" / "identity").write_text("fixture")
        (self.secrets / "b" / "known_hosts").unlink()
        with self.assertRaises(ValueError):
            self.load()
        (self.secrets / "b" / "identity").unlink()
        (self.secrets / "b").rmdir()
        (self.secrets / "b").symlink_to(self.secrets / "a", target_is_directory=True)
        with self.assertRaises(ValueError):
            self.load()
        with patch.dict(os.environ, {"INSPECTOR_HOST_MODE": "legacy"}):
            self.assertIsNone(configured_registry())
        with patch.dict(os.environ, {"INSPECTOR_HOST_MODE": "broken"}):
            with self.assertRaises(ValueError):
                configured_registry()
        with patch.dict(os.environ, {"INSPECTOR_HOST_MODE": "multi"}), patch(
            "hosts.load_multi_registry", return_value=Registry({}, "a")
        ) as load:
            self.assertIsInstance(configured_registry(), Registry)
            load.assert_called_once()
        with patch.dict(os.environ, {"INSPECTOR_HOST_MODE": "multi"}), patch(
            "hosts.load_multi_registry", side_effect=ValueError("missing")
        ):
            with self.assertRaises(ValueError):
                configured_registry()


class InspectorTests(unittest.TestCase):
    def test_registered_tools(self):
        tools = asyncio.run(server.mcp.list_tools())
        self.assertEqual(
            {tool.name for tool in tools},
            {"inspector_status", "inspect_server", "list_hosts", "list_checks", "inspect", "inspect_batch"},
        )

    def test_catalog_complete_and_consistent(self):
        self.assertEqual(set(CHECKS), set(EXPECTED_COMMANDS))
        self.assertEqual(len(CHECKS), 15)
        self.assertEqual(set(LEGACY_OPERATIONS.values()), {
            "system.identity", "system.uptime", "network.listeners", "system.services",
        })
        entries = server.list_checks()
        self.assertEqual({entry["check_id"] for entry in entries}, set(CHECKS))
        for entry in entries:
            self.assertTrue(entry["description"])
            self.assertTrue(entry["category"])
            self.assertIs(entry["requires_elevation"], False)
            self.assertEqual(entry["timeout_seconds"], 15)
            self.assertEqual(entry["max_output_bytes"], 16384)

    def test_every_check_uses_exact_ssh_operation_and_result_schema(self):
        with (
            patch.object(server, "SSH_TARGET", "sg-audit@192.0.2.1"),
            patch.object(server, "HOST_LABEL", "test-host"),
            patch.object(server, "run_bounded", return_value=Captured(0, b"ok\n", b"", False)) as run,
        ):
            for check_id in CHECKS:
                with self.subTest(check_id=check_id):
                    result = server.inspect(check_id)
                    command = run.call_args.args[0]
                    self.assertEqual(command[-2:], ["sg-audit@192.0.2.1", check_id])
                    self.assertEqual(command[0], "/usr/bin/ssh")
                    self.assertIn("StrictHostKeyChecking=yes", command)
                    self.assertIn("BatchMode=yes", command)
                    self.assertIn("ClearAllForwardings=yes", command)
                    self.assertEqual(run.call_args.kwargs["timeout"], 15)
                    self.assertEqual(run.call_args.kwargs["stdout_limit"], 16384)
                    self.assertEqual(result["host"], "test-host")
                    self.assertEqual(result["check_id"], check_id)
                    self.assertEqual(result["status"], "success")
                    self.assertEqual(result["exit_code"], 0)
                    self.assertEqual(result["output"], "ok\n")
                    self.assertIs(result["truncated"], False)
                    self.assertIs(result["stderr_truncated"], False)
                    self.assertIsNone(result["error"])
                    self.assertTrue(result["collected_at"].endswith("+00:00"))

    def test_unknown_malformed_and_injected_requests_do_not_reach_ssh(self):
        with patch.object(server, "run_bounded") as run:
            for value in ("", "whoami", "system.os; id", "system.cpu && reboot",
                          "system.block_devices --output SERIAL", "network.interfaces; id",
                          "network.routes_ipv4 -j", "/bin/sh", "../etc/passwd", None,
                          1, ["system.os"]):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    server.inspect(value)
            for value in ("whoami", "uptime; id", "services && reboot", "/bin/sh", None):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    server.inspect_server(value)
            run.assert_not_called()

    def test_missing_target_and_transport_failures(self):
        with patch.object(server, "SSH_TARGET", ""), patch.object(server, "run_bounded") as run:
            result = server.inspect("system.os")
            self.assertEqual(result["status"], "error")
            self.assertIsNone(result["exit_code"])
            self.assertIn("not configured", result["error"])
            with self.assertRaisesRegex(RuntimeError, "not configured"):
                server.inspect_server("uptime")
            run.assert_not_called()
        with patch.object(server, "SSH_TARGET", "host"):
            for failure, message in (
                (subprocess.TimeoutExpired("ssh", 15), "timed out"),
                (OSError("private path"), "could not start"),
            ):
                with patch.object(server, "run_bounded", side_effect=failure):
                    result = server.inspect("system.os")
                    self.assertEqual(result["status"], "error")
                    self.assertIn(message, result["error"])
                    self.assertNotIn("private path", result["error"])

    def test_nonzero_and_truncation_are_not_success(self):
        with patch.object(server, "SSH_TARGET", "host"):
            cases = [
                (Captured(255, b"", b"\x1b[31mSSH failed\x1b[0m\x00" + b"x" * 2000, False),
                 "error", False),
                (Captured(-9, b"x" * 16384, b"", True), "incomplete", True),
                (Captured(125, b"x", b"ERROR: diagnostic output truncated\n", False),
                 "incomplete", True),
                (Captured(125, b"", b"ordinary exit 125", False), "error", False),
                (Captured(7, b"detail", b"e" * 1024, False, True), "error", False),
                (Captured(0, b"complete", b"WARNING\nERROR: diagnostic stderr truncated\n",
                          False), "success", False),
            ]
            for captured, status, truncated in cases:
                with patch.object(server, "run_bounded", return_value=captured):
                    result = server.inspect("system.os")
                    self.assertEqual(result["status"], status)
                    self.assertIs(result["truncated"], truncated)
                    if result["error"] is not None:
                        self.assertLessEqual(len(result["error"]), 1024)
                        self.assertNotIn("\x1b", result["error"])
                        self.assertNotIn("\x00", result["error"])
                    if captured.stderr_truncated:
                        self.assertTrue(result["stderr_truncated"])
                        self.assertIn("stderr truncated", result["error"])
                        self.assertEqual(result["exit_code"], 7)
                    if b"diagnostic stderr truncated" in captured.stderr:
                        self.assertTrue(result["stderr_truncated"])
                        self.assertEqual(result["output"], "complete")

    def test_decoded_output_respects_utf8_byte_limit(self):
        limit = CHECKS["system.os"].max_output_bytes
        cases = (
            (b"\xff" * limit, "\ufffd" * (limit // 3), "incomplete", True),
            (b"a" * (limit - 1) + b"\xe2", "a" * (limit - 1), "incomplete", True),
            (b"a" * (limit - 3) + "€".encode(), "a" * (limit - 3) + "€", "success", False),
            (b"a" * limit, "a" * limit, "success", False),
        )
        with patch.object(server, "SSH_TARGET", "host"):
            for raw, expected, status, truncated in cases:
                with self.subTest(raw_suffix=raw[-4:]), patch.object(
                    server, "run_bounded", return_value=Captured(0, raw, b"", False)
                ):
                    result = server.inspect("system.os")
                    self.assertEqual(result["output"], expected)
                    self.assertLessEqual(len(result["output"].encode("utf-8")), limit)
                    self.assertEqual(result["status"], status)
                    self.assertIs(result["truncated"], truncated)
                    self.assertEqual(result["exit_code"], 0)
                    self.assertEqual(
                        result["error"], "Diagnostic output was truncated" if truncated else None
                    )
            with patch.object(server, "run_bounded", return_value=Captured(
                7, b"\xff" * limit, b"diagnostic failed", False
            )):
                result = server.inspect("system.os")
                self.assertEqual(result["status"], "incomplete")
                self.assertEqual(result["exit_code"], 7)
                self.assertEqual(result["error"], "diagnostic failed")

    def test_empty_routes_and_devices_are_successful(self):
        with patch.object(server, "SSH_TARGET", "host"):
            for check_id, output in (
                ("system.block_devices", b'{"blockdevices":[]}\n'),
                ("network.routes_ipv4", b"[]\n"),
                ("network.routes_ipv6", b"[]\n"),
            ):
                with self.subTest(check_id=check_id), patch.object(
                    server, "run_bounded", return_value=Captured(0, output, b"", False)
                ):
                    result = server.inspect(check_id)
                    self.assertEqual(result["status"], "success")
                    self.assertEqual(result["output"], output.decode())

    def test_batch_validation_and_partial_failure(self):
        with patch.object(server, "run_bounded") as run:
            for ids in ([], ["system.os"] * 6, ["system.os", "bad"], "system.os",
                        [None], [1], None):
                with self.subTest(ids=ids), self.assertRaises(ValueError):
                    server.inspect_batch(ids)
            run.assert_not_called()
        responses = [
            Captured(0, b"first", b"", False),
            Captured(1, b"", b"failed", False),
            Captured(0, b"third", b"", False),
        ]
        with (
            patch.object(server, "SSH_TARGET", "host"),
            patch.object(server, "run_bounded", side_effect=responses) as run,
        ):
            results = server.inspect_batch(["system.os", "system.kernel", "system.cpu"])
            self.assertEqual([r["status"] for r in results], ["success", "error", "success"])
            self.assertEqual([r["output"] for r in results], ["first", "", "third"])
            self.assertEqual(run.call_count, 3)

    def test_legacy_compatibility(self):
        self.assertEqual(set(server.inspector_status()["operations"]), set(LEGACY_OPERATIONS))
        with (
            patch.object(server, "SSH_TARGET", "host"),
            patch.object(server, "run_bounded", return_value=Captured(0, b"ok", b"", False)) as run,
        ):
            for operation in LEGACY_OPERATIONS:
                result = server.inspect_server(operation)
                self.assertEqual(run.call_args.args[0][-1], operation)
                self.assertEqual(result, {
                    "host": server.HOST_LABEL, "operation": operation,
                    "exit_code": 0, "output": "ok",
                })
        with (
            patch.object(server, "SSH_TARGET", "host"),
            patch.object(server, "run_bounded", return_value=Captured(1, b"", b"failed", False)),
        ):
            with self.assertRaisesRegex(RuntimeError, "failed"):
                server.inspect_server("uptime")

    def test_bounded_local_capture_and_timeout(self):
        command = [sys.executable, "-c", "import sys;sys.stdout.write('x'*50000)"]
        result = run_bounded(command, timeout=2, stdout_limit=1024,
                             stderr_limit=128, env=dict(os.environ))
        self.assertTrue(result.truncated)
        self.assertEqual(len(result.stdout), 1024)
        noisy = run_bounded(
            [sys.executable, "-c",
             "import sys;sys.stderr.write('e'*50000);sys.stdout.write('ok');sys.exit(7)"],
            timeout=2, stdout_limit=1024, stderr_limit=128, env=dict(os.environ),
        )
        self.assertEqual(noisy.returncode, 7)
        self.assertEqual(noisy.stdout, b"ok")
        self.assertFalse(noisy.truncated)
        self.assertTrue(noisy.stderr_truncated)
        self.assertEqual(len(noisy.stderr), 128)
        with self.assertRaises(subprocess.TimeoutExpired):
            run_bounded([sys.executable, "-c", "import time;time.sleep(2)"],
                        timeout=0.1, stdout_limit=1024, stderr_limit=128,
                        env=dict(os.environ))

    def test_bounded_deadline_after_read_and_os_error_cleanup(self):
        class EmptySelector:
            def __init__(self):
                self.calls = 0

            def register(self, *_):
                pass

            def get_map(self):
                self.calls += 1
                return self.calls == 1

            def select(self, _):
                return []

            def close(self):
                pass

        command = [sys.executable, "-c", "import time;time.sleep(30)"]
        with patch("bounded.selectors.DefaultSelector", EmptySelector), \
             patch("bounded.time.monotonic", side_effect=[0, 0, 10]):
            with self.assertRaises(subprocess.TimeoutExpired):
                run_bounded(command, timeout=1, stdout_limit=1, stderr_limit=1,
                            env=dict(os.environ))
        with patch("bounded.os.set_blocking", side_effect=OSError("read error")):
            with self.assertRaises(OSError):
                run_bounded(command, timeout=1, stdout_limit=1, stderr_limit=1,
                            env=dict(os.environ))

    def test_bounded_exact_limits_and_child_termination(self):
        for stdout_size, stderr_size, expected_stdout, expected_stderr in (
            (16, 16, False, False),
            (17, 0, True, False),
            (0, 17, False, True),
        ):
            with self.subTest(stdout_size=stdout_size):
                result = run_bounded(
                    [sys.executable, "-c",
                     f"import sys;sys.stderr.write('e'*{stderr_size});"
                     f"sys.stdout.write('x'*{stdout_size})"],
                    timeout=2, stdout_limit=16, stderr_limit=16,
                    env=dict(os.environ),
                )
                self.assertEqual(len(result.stdout), min(stdout_size, 16))
                self.assertEqual(len(result.stderr), min(stderr_size, 16))
                self.assertIs(result.truncated, expected_stdout)
                self.assertIs(result.stderr_truncated, expected_stderr)
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "pid"
            command = [sys.executable, "-c",
                       "import os, pathlib, sys, time;"
                       f"pathlib.Path({str(pid_file)!r}).write_text(str(os.getpid()));"
                       "sys.stdout.write('x'*50000);sys.stdout.flush();time.sleep(30)"]
            result = run_bounded(command, timeout=2, stdout_limit=16,
                                 stderr_limit=16, env=dict(os.environ))
            self.assertTrue(result.truncated)
            with self.assertRaises(ProcessLookupError):
                os.kill(int(pid_file.read_text()), 0)

    def test_server_entry_point(self):
        with patch.object(server.MCPServer, "run") as run:
            runpy.run_path(str(Path(server.__file__)), run_name="__main__")
        self.assertEqual(run.call_args.kwargs["transport"], "streamable-http")
        self.assertTrue(run.call_args.kwargs["stateless_http"])


class DispatcherTests(unittest.TestCase):
    def test_execution_deadlines_and_os_error_cleanup(self):
        class EmptySelector:
            def __init__(self):
                self.calls = 0

            def register(self, *_):
                pass

            def get_map(self):
                self.calls += 1
                return self.calls == 1

            def select(self, _):
                return []

            def close(self):
                pass

        command = [sys.executable, "-c", "import time;time.sleep(30)"]
        with patch.object(dispatcher.selectors, "DefaultSelector", EmptySelector), \
             patch.object(dispatcher.time, "monotonic", side_effect=[0, 0, 11]):
            with self.assertRaises(subprocess.TimeoutExpired):
                dispatcher.execute(command)
        with patch.object(dispatcher.time, "monotonic", side_effect=[0, 11]):
            with self.assertRaises(subprocess.TimeoutExpired):
                dispatcher.execute(command)
        with patch.object(dispatcher.os, "set_blocking", side_effect=OSError("read error")):
            with self.assertRaises(OSError):
                dispatcher.execute(command)

    def test_exact_dispatcher_output_limit_and_child_termination(self):
        exact = dispatcher.execute([sys.executable, "-c",
                                    f"import sys;sys.stdout.write('x'*{dispatcher.OUTPUT_LIMIT});"
                                    f"sys.stderr.write('e'*{dispatcher.ERROR_LIMIT})"])
        self.assertEqual(len(exact[1]), dispatcher.OUTPUT_LIMIT)
        self.assertEqual(len(exact[2]), dispatcher.ERROR_LIMIT)
        self.assertFalse(exact[3])
        self.assertFalse(exact[4])
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "pid"
            command = [sys.executable, "-c",
                       "import os, pathlib, sys, time;"
                       f"pathlib.Path({str(pid_file)!r}).write_text(str(os.getpid()));"
                       f"sys.stdout.write('x'*{dispatcher.OUTPUT_LIMIT + 1});"
                       "sys.stdout.flush();time.sleep(30)"]
            result = dispatcher.execute(command)
            self.assertTrue(result[3])
            with self.assertRaises(ProcessLookupError):
                os.kill(int(pid_file.read_text()), 0)

    def test_main_rejections_and_process_errors(self):
        with patch.dict(os.environ, {"SSH_ORIGINAL_COMMAND": "unsupported"}):
            with patch.object(dispatcher.sys, "stderr", io.StringIO()) as stderr:
                self.assertEqual(dispatcher.main(), 126)
                self.assertIn("DENIED", stderr.getvalue())
        with patch.dict(os.environ, {"SSH_ORIGINAL_COMMAND": "identity"}):
            for error, code, message in (
                (subprocess.TimeoutExpired("id", 1), 124, "timeout"),
                (OSError("private path"), 127, "could not start"),
            ):
                with patch.object(dispatcher, "execute", side_effect=error), \
                     patch.object(dispatcher.sys, "stderr", io.StringIO()) as stderr:
                    self.assertEqual(dispatcher.main(), code)
                    self.assertIn(message, stderr.getvalue())
                    self.assertNotIn("private path", stderr.getvalue())
            with patch.object(dispatcher, "execute", return_value=(3, b"out", b"error", False, False)), \
                 patch.object(dispatcher.sys, "stdout", SimpleNamespace(buffer=io.BytesIO())), \
                 patch.object(dispatcher.sys, "stderr", SimpleNamespace(buffer=io.BytesIO())) as stderr:
                self.assertEqual(dispatcher.main(), 3)
                self.assertEqual(stderr.buffer.getvalue(), b"error")

    def test_dispatcher_entry_point(self):
        with patch.dict(os.environ, {"SSH_ORIGINAL_COMMAND": "invalid"}), \
             patch.object(sys, "stderr", io.StringIO()):
            with self.assertRaises(SystemExit) as exited:
                runpy.run_path(str(DISPATCHER_PATH), run_name="__main__")
        self.assertEqual(exited.exception.code, 126)

    def test_complete_independent_fixed_allowlist(self):
        expected = dict(EXPECTED_COMMANDS)
        expected.update({legacy: EXPECTED_COMMANDS[check_id]
                         for legacy, check_id in LEGACY_OPERATIONS.items()})
        self.assertEqual(dispatcher.COMMANDS, expected)
        self.assertEqual(dispatcher.OUTPUT_LIMIT, 16384)
        self.assertEqual(dispatcher.TIMEOUT, 10)

    def test_every_operation_dispatches_exact_argv(self):
        for operation, argv in dispatcher.COMMANDS.items():
            with self.subTest(operation=operation):
                with patch.dict(os.environ, {"SSH_ORIGINAL_COMMAND": operation}):
                    with patch.object(dispatcher, "execute", return_value=(0, b"", b"", False, False)) as run:
                        self.assertEqual(dispatcher.main(), 0)
                        run.assert_called_once_with(argv)

    def test_dispatcher_rejects_unknown_and_injection_independently(self):
        for operation in ("", "system.os /etc/shadow", "uptime; id", "system.cpu && id",
                          "/bin/sh", "system.os\nidentity", "../etc/passwd"):
            with self.subTest(operation=operation):
                env = dict(os.environ, SSH_ORIGINAL_COMMAND=operation)
                result = subprocess.run(
                    [sys.executable, "-I", str(DISPATCHER_PATH)],
                    env=env, capture_output=True, timeout=5,
                )
                self.assertEqual(result.returncode, 126)
                self.assertIn(b"DENIED", result.stderr)

    def test_dispatcher_real_identity_and_os(self):
        for operation, expected in (("identity", b"uid="), ("system.os", b"ID=")):
            result = subprocess.run(
                [sys.executable, "-I", str(DISPATCHER_PATH)],
                env=dict(os.environ, SSH_ORIGINAL_COMMAND=operation),
                capture_output=True, timeout=5,
            )
            self.assertEqual(result.returncode, 0)
            self.assertIn(expected, result.stdout)

    def test_dispatcher_truncates_and_reports_incomplete(self):
        result = dispatcher.execute([sys.executable, "-c",
                                     "import sys;sys.stdout.write('x'*50000)"])
        self.assertTrue(result[3])
        self.assertEqual(len(result[1]), dispatcher.OUTPUT_LIMIT)
        with patch.dict(os.environ, {"SSH_ORIGINAL_COMMAND": "system.os"}):
            with patch.object(dispatcher, "execute", return_value=result):
                with patch.object(dispatcher.sys, "stdout", SimpleNamespace(buffer=io.BytesIO())):
                    with patch.object(dispatcher.sys, "stderr", SimpleNamespace(buffer=io.BytesIO())) as stderr:
                        self.assertEqual(dispatcher.main(), 125)
                        self.assertIn(b"output truncated", stderr.buffer.getvalue())

    def test_dispatcher_stderr_overflow_preserves_exit_and_stdout(self):
        result = dispatcher.execute([
            sys.executable, "-c",
            "import sys;sys.stderr.write('e'*50000);sys.stdout.write('ok');sys.exit(7)",
        ])
        self.assertEqual(result[0], 7)
        self.assertEqual(result[1], b"ok")
        self.assertFalse(result[3])
        self.assertTrue(result[4])
        with patch.dict(os.environ, {"SSH_ORIGINAL_COMMAND": "system.os"}):
            with patch.object(dispatcher, "execute", return_value=result):
                with patch.object(dispatcher.sys, "stdout", SimpleNamespace(buffer=io.BytesIO())) as stdout:
                    with patch.object(dispatcher.sys, "stderr", SimpleNamespace(buffer=io.BytesIO())) as stderr:
                        self.assertEqual(dispatcher.main(), 7)
                        self.assertEqual(stdout.buffer.getvalue(), b"ok")
                        self.assertIn(b"stderr truncated", stderr.buffer.getvalue())


if __name__ == "__main__":
    unittest.main()
