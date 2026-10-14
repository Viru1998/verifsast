# CWE-22: Path Traversal — pathlib.Path(base) / user_path without realpath check
# Vulnerability: the / operator (PurePosixPath.__truediv__) still allows ".."
# components; without calling .resolve() and checking confinement the path escapes.

import pathlib


BASE = pathlib.Path("/var/www/files")


def read_file(user_path):
    """
    Read a file under BASE using pathlib.
    VULNERABLE: no .resolve() / is_relative_to() check; ".." is still honoured.
    """
    # VULNERABLE: pathlib / operator does not strip ".." components
    full = BASE / user_path
    return full.read_text(encoding="utf-8")


def write_file(user_path, content):
    """Write content to a user-specified path under BASE — also vulnerable."""
    full = BASE / user_path
    # VULNERABLE: full might be outside BASE if user_path = "../../etc/motd"
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_text(content, encoding="utf-8")
    return str(full)


def get_file_size(user_path):
    """Return the size of a file — no boundary check."""
    full = BASE / user_path
    # VULNERABLE: stat() follows the traversal
    return full.stat().st_size


if __name__ == "__main__":
    try:
        # Attack: user_path = "../../etc/hostname"
        content = read_file("../../etc/hostname")
        print(content)
    except OSError as exc:
        print(f"Error: {exc}")
