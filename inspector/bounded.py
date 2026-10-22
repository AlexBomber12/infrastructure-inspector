"""Capture a process without buffering unlimited output."""

import os
import selectors
import subprocess
import time
from dataclasses import dataclass


@dataclass
class Captured:
    returncode: int
    stdout: bytes
    stderr: bytes
    truncated: bool
    stderr_truncated: bool = False


def run_bounded(command, *, timeout, stdout_limit, stderr_limit, env):
    process = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
        stdin=subprocess.DEVNULL, close_fds=True,
    )
    output = {process.stdout: bytearray(), process.stderr: bytearray()}
    limits = {process.stdout: stdout_limit, process.stderr: stderr_limit}
    deadline = time.monotonic() + timeout
    truncated = False
    stderr_truncated = False
    selector = selectors.DefaultSelector()
    try:
        for stream in output:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, timeout)
            for key, _ in selector.select(remaining):
                stream = key.fileobj
                chunk = os.read(stream.fileno(), 4096)
                if not chunk:
                    selector.unregister(stream)
                    continue
                room = limits[stream] - len(output[stream])
                output[stream].extend(chunk[:max(room, 0)])
                if len(chunk) > room:
                    if stream is process.stdout:
                        truncated = True
                        break
                    stderr_truncated = True
            if truncated:
                break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(command, timeout)
        if truncated:
            process.kill()
        returncode = process.wait(timeout=remaining)
        return Captured(returncode, bytes(output[process.stdout]),
                        bytes(output[process.stderr]), truncated, stderr_truncated)
    except (subprocess.TimeoutExpired, OSError):
        process.kill()
        process.wait()
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
