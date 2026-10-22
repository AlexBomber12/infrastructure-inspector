import os
import subprocess
import sys

COMMANDS = {
    "identity": ["/usr/bin/id"],
    "uptime": ["/usr/bin/uptime"],
    "listeners": ["/usr/bin/ss", "-H", "-lnt"],
    "services": [
        "/usr/bin/systemctl",
        "list-units",
        "--type=service",
        "--state=running",
        "--no-pager",
        "--plain",
        "--no-legend",
    ],
}

request = os.environ.get("SSH_ORIGINAL_COMMAND", "")

if request not in COMMANDS:
    print("DENIED: command not allowed", file=sys.stderr)
    sys.exit(126)

try:
    result = subprocess.run(
        COMMANDS[request],
        capture_output=True,
        text=True,
        timeout=10,
        env={"PATH": "/usr/bin:/bin", "LANG": "C"},
    )
except subprocess.TimeoutExpired:
    print("ERROR: timeout", file=sys.stderr)
    sys.exit(124)

sys.stdout.write(result.stdout[:32768])
sys.stderr.write(result.stderr[:4096])
sys.exit(result.returncode)
