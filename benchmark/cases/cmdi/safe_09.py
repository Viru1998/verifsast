# CWE-78: Safe — input validated against strict regex before use in subprocess
# The regex allows only safe characters; anything else is rejected before
# the value reaches the command.

import re
import subprocess

# Regex for hostnames / IP addresses: alphanumeric, hyphens, dots only
SAFE_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9.\-]{1,253}$")

# Regex for alphanumeric identifiers (e.g. usernames, short labels)
SAFE_IDENTIFIER_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")


def ping_host(host):
    """Ping a host after validating against a hostname regex."""
    if not SAFE_HOSTNAME_RE.match(host):
        raise ValueError(f"Invalid hostname: {host!r}")

    # SAFE: host is validated; list args prevent further injection
    result = subprocess.run(
        ["ping", "-c", "2", host],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout


def tail_log(log_name):
    """Tail a named application log — name validated before use."""
    if not SAFE_IDENTIFIER_RE.match(log_name):
        raise ValueError(f"Invalid log name: {log_name!r}")

    log_path = f"/var/log/{log_name}.log"

    # SAFE: list args + validated name
    result = subprocess.run(
        ["tail", "-n", "100", log_path],
        capture_output=True,
        text=True,
    )
    return result.stdout


if __name__ == "__main__":
    print(ping_host("8.8.8.8"))
    try:
        ping_host("8.8.8.8; id")   # rejected by regex
    except ValueError as exc:
        print(f"Rejected: {exc}")
