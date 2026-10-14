# CWE-22: Safe — os.path.realpath() + assert startswith(base)
# Resolves symlinks and ".." before checking confinement.

import os


BASE_DIR = os.path.realpath("/var/www/uploads")


def read_file(filename):
    """
    Read a file from BASE_DIR, enforcing confinement with realpath.
    SAFE: realpath resolves all ".." and symlink hops before the check.
    """
    # Resolve the absolute, canonical path
    requested = os.path.realpath(os.path.join(BASE_DIR, filename))

    # Confinement check — reject anything outside BASE_DIR
    if not requested.startswith(BASE_DIR + os.sep):
        raise PermissionError(f"Access denied: {filename!r} is outside the allowed directory")

    with open(requested, "rb") as f:
        return f.read()


def write_file(filename, data):
    """Write a file safely — same realpath confinement."""
    requested = os.path.realpath(os.path.join(BASE_DIR, filename))

    if not requested.startswith(BASE_DIR + os.sep):
        raise PermissionError(f"Access denied: {filename!r}")

    os.makedirs(os.path.dirname(requested), exist_ok=True)
    with open(requested, "wb") as f:
        f.write(data)


if __name__ == "__main__":
    # Legitimate use
    try:
        data = read_file("report.pdf")
        print(f"Read {len(data)} bytes")
    except OSError as exc:
        print(exc)

    # Attack attempt
    try:
        read_file("../../etc/passwd")
    except PermissionError as exc:
        print(f"Blocked: {exc}")
