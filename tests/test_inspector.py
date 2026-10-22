import asyncio
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import server


class InspectorTests(unittest.TestCase):

    def test_registered_tools(self):
        tools = asyncio.run(server.mcp.list_tools())
        names = {tool.name for tool in tools}
        self.assertEqual(
            names,
            {"inspector_status", "inspect_server"},
        )

    def test_operation_allowlist(self):
        self.assertEqual(
            set(server.OPERATIONS),
            {"identity", "uptime", "listeners", "services"},
        )

    def test_ssh_command_construction(self):
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="test output\n",
            stderr="",
        )

        with (
            patch.object(server, "SSH_TARGET", "sg-audit@192.0.2.1"),
            patch.object(server, "HOST_LABEL", "test-server"),
            patch.object(
                server.subprocess,
                "run",
                return_value=completed,
            ) as execute,
        ):
            for operation in server.OPERATIONS:
                result = server.inspect_server(operation)

                command = execute.call_args.args[0]
                options = execute.call_args.kwargs

                self.assertEqual(command[0], "/usr/bin/ssh")
                self.assertEqual(
                    command[-2:],
                    ["sg-audit@192.0.2.1", operation],
                )
                self.assertIn("StrictHostKeyChecking=yes", command)
                self.assertIn("BatchMode=yes", command)
                self.assertIn("ClearAllForwardings=yes", command)
                self.assertEqual(options["timeout"], 15)
                self.assertNotIn("shell", options)

                self.assertEqual(result["host"], "test-server")
                self.assertEqual(result["exit_code"], 0)
                self.assertEqual(result["operation"], operation)

    def test_rejects_arbitrary_commands(self):
        with patch.object(server.subprocess, "run") as execute:
            for operation in (
                "whoami",
                "uptime; id",
                "services && reboot",
                "/bin/sh",
            ):
                with self.assertRaises(ValueError):
                    server.inspect_server(operation)

            execute.assert_not_called()

    def test_rejects_missing_target(self):
        with (
            patch.object(server, "SSH_TARGET", ""),
            patch.object(server.subprocess, "run") as execute,
        ):
            with self.assertRaises(RuntimeError):
                server.inspect_server("uptime")

            execute.assert_not_called()

    def test_ssh_failure(self):
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=255,
            stdout="",
            stderr="SSH connection failed",
        )

        with (
            patch.object(server, "SSH_TARGET", "sg-audit@192.0.2.1"),
            patch.object(
                server.subprocess,
                "run",
                return_value=completed,
            ),
        ):
            with self.assertRaises(RuntimeError):
                server.inspect_server("uptime")

    def test_ssh_timeout(self):
        with (
            patch.object(server, "SSH_TARGET", "sg-audit@192.0.2.1"),
            patch.object(
                server.subprocess,
                "run",
                side_effect=subprocess.TimeoutExpired("ssh", 15),
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "timed out"):
                server.inspect_server("uptime")

    def test_response_limit(self):
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="x" * 20000,
            stderr="",
        )

        with (
            patch.object(server, "SSH_TARGET", "sg-audit@192.0.2.1"),
            patch.object(
                server.subprocess,
                "run",
                return_value=completed,
            ),
        ):
            result = server.inspect_server("uptime")
            self.assertEqual(len(result["output"]), 16384)


class DispatcherTests(unittest.TestCase):

    def test_dispatcher_rejects_shell_injection(self):
        dispatcher = (
            Path(__file__).resolve().parents[1]
            / "host"
            / "sg-audit-dispatch.py"
        )

        env = dict(os.environ)
        env["SSH_ORIGINAL_COMMAND"] = "uptime; id"

        result = subprocess.run(
            [sys.executable, "-I", str(dispatcher)],
            env=env,
            capture_output=True,
            text=True,
            timeout=5,
        )

        self.assertEqual(result.returncode, 126)
        self.assertIn("DENIED", result.stderr)

    def test_dispatcher_allows_identity(self):
        dispatcher = (
            Path(__file__).resolve().parents[1]
            / "host"
            / "sg-audit-dispatch.py"
        )

        env = dict(os.environ)
        env["SSH_ORIGINAL_COMMAND"] = "identity"

        result = subprocess.run(
            [sys.executable, "-I", str(dispatcher)],
            env=env,
            capture_output=True,
            text=True,
            timeout=5,
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("uid=", result.stdout)


if __name__ == "__main__":
    unittest.main()
