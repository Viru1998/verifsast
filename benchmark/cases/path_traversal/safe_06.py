# CWE-22: Safe — hardcoded file path, no user input
# No traversal is possible because every path is a compile-time literal.

import os


def read_app_config():
    """Read the application configuration — fully hardcoded path."""
    # SAFE: literal path, zero user-controlled data
    with open("/etc/myapp/config.json", "r", encoding="utf-8") as f:
        return f.read()


def read_default_template():
    """Read the default HTML template."""
    # SAFE: hardcoded path
    with open("/var/www/templates/default.html", "r", encoding="utf-8") as f:
        return f.read()


def get_version():
    """Read the application version file."""
    with open("/opt/myapp/VERSION", "r") as f:
        return f.read().strip()


def read_license():
    """Read the license file."""
    with open("/opt/myapp/LICENSE", "r", encoding="utf-8") as f:
        return f.read()


if __name__ == "__main__":
    try:
        print(get_version())
    except OSError as exc:
        print(f"Could not read version: {exc}")

    try:
        print(read_app_config()[:100])
    except OSError as exc:
        print(f"Config not found: {exc}")
