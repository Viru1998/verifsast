# CWE-22: Safe — pathlib.Path.resolve() + is_relative_to()
# Python 3.9+ is_relative_to() is the idiomatic confinement check.

import pathlib


BASE = pathlib.Path("/var/www/uploads").resolve()


def read_file(user_path):
    """
    Read a file under BASE using pathlib with a proper confinement check.
    SAFE: resolve() canonicalises the path; is_relative_to() enforces the boundary.
    """
    full = (BASE / user_path).resolve()

    # SAFE: is_relative_to() checks that full is inside BASE after resolution
    if not full.is_relative_to(BASE):
        raise PermissionError(f"Access denied: path escapes the allowed directory")

    return full.read_bytes()


def write_file(user_path, content: bytes):
    """Write a file — same confinement pattern."""
    full = (BASE / user_path).resolve()

    if not full.is_relative_to(BASE):
        raise PermissionError("Access denied")

    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_bytes(content)


def list_files(subdir=""):
    """List files within a subdirectory of BASE."""
    target = (BASE / subdir).resolve()

    if not target.is_relative_to(BASE):
        raise PermissionError("Access denied")

    return [p.name for p in target.iterdir() if p.is_file()]


if __name__ == "__main__":
    try:
        data = read_file("report.pdf")
        print(f"Read {len(data)} bytes")
    except OSError as exc:
        print(exc)

    try:
        read_file("../../etc/passwd")
    except PermissionError as exc:
        print(f"Blocked: {exc}")
