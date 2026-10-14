# CWE-78: Safe — hardcoded command, no user input
# No vulnerability: every shell command is a fixed string literal with
# zero user-controlled components.

import subprocess
import os


def get_system_uptime():
    """Return system uptime — hardcoded command, no user data."""
    # SAFE: literal command, no variables
    result = subprocess.run(["uptime"], capture_output=True, text=True)
    return result.stdout.strip()


def get_disk_usage():
    """Check disk usage on root filesystem."""
    # SAFE: hardcoded arguments only
    result = subprocess.run(
        ["df", "-h", "/"],
        capture_output=True,
        text=True,
    )
    return result.stdout


def reload_nginx():
    """Send SIGHUP to nginx to reload its config."""
    # SAFE: fixed command, no interpolation
    result = subprocess.run(
        ["nginx", "-s", "reload"],
        capture_output=True,
        text=True,
    )
    return result.returncode


def rotate_logs():
    """Run logrotate with the system config."""
    result = subprocess.run(
        ["logrotate", "/etc/logrotate.conf"],
        capture_output=True,
        text=True,
    )
    return result.returncode


if __name__ == "__main__":
    print(get_system_uptime())
    print(get_disk_usage())
