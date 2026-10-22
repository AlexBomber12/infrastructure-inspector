"""Standalone ForceCommand dispatcher. Install this file on the target host."""

import os
import selectors
import subprocess
import sys
import time

# This is the target host's independent authorization boundary. Do not import
# the MCP catalog or accept arguments from SSH_ORIGINAL_COMMAND.
COMMANDS = {
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
}
COMMANDS.update({
    "identity": COMMANDS["system.identity"],
    "uptime": COMMANDS["system.uptime"],
    "listeners": COMMANDS["network.listeners"],
    "services": COMMANDS["system.services"],
})

OUTPUT_LIMIT = 16384
ERROR_LIMIT = 1024
TIMEOUT = 10


def execute(command):
    process = subprocess.Popen(
        command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env={"PATH": "/usr/bin:/bin", "LANG": "C"},
        close_fds=True,
    )
    buffers = {process.stdout: bytearray(), process.stderr: bytearray()}
    limits = {process.stdout: OUTPUT_LIMIT, process.stderr: ERROR_LIMIT}
    deadline = time.monotonic() + TIMEOUT
    truncated = False
    stderr_truncated = False
    selector = selectors.DefaultSelector()
    try:
        for stream in buffers:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, TIMEOUT)
            for key, _ in selector.select(remaining):
                stream = key.fileobj
                chunk = os.read(stream.fileno(), 4096)
                if not chunk:
                    selector.unregister(stream)
                    continue
                room = limits[stream] - len(buffers[stream])
                buffers[stream].extend(chunk[:max(room, 0)])
                if len(chunk) > room:
                    if stream is process.stdout:
                        truncated = True
                        break
                    stderr_truncated = True
            if truncated:
                break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(command, TIMEOUT)
        if truncated:
            process.kill()
        returncode = process.wait(timeout=remaining)
        return (returncode, bytes(buffers[process.stdout]),
                bytes(buffers[process.stderr]), truncated, stderr_truncated)
    except (subprocess.TimeoutExpired, OSError):
        process.kill()
        process.wait()
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()


def main():
    request = os.environ.get("SSH_ORIGINAL_COMMAND", "")
    if request not in COMMANDS:
        print("DENIED: command not allowed", file=sys.stderr)
        return 126
    try:
        returncode, stdout, stderr, truncated, stderr_truncated = execute(COMMANDS[request])
    except subprocess.TimeoutExpired:
        print("ERROR: timeout", file=sys.stderr)
        return 124
    except OSError:
        print("ERROR: diagnostic could not start", file=sys.stderr)
        return 127
    sys.stdout.buffer.write(stdout)
    if truncated:
        sys.stderr.buffer.write(b"ERROR: diagnostic output truncated\n")
        sys.stderr.buffer.write(stderr[:ERROR_LIMIT - 35])
        return 125
    if stderr_truncated:
        marker = b"\nERROR: diagnostic stderr truncated\n"
        sys.stderr.buffer.write(stderr[:ERROR_LIMIT - len(marker)] + marker)
    else:
        sys.stderr.buffer.write(stderr)
    return returncode


if __name__ == "__main__":
    sys.exit(main())
