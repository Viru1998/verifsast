# CWE-22: Path Traversal — os.path.join(base, user_path) without validation
# Vulnerability: os.path.join() does NOT prevent traversal when user_path
# starts with "/" or contains ".." segments.

import os


BASE_DIR = "/var/www/uploads"


def download_file(user_path):
    """
    Join base dir with a user-provided path and read the file.
    VULNERABLE: os.path.join does not prevent "../" or absolute paths.
    """
    # VULNERABLE: if user_path is "/etc/passwd" or "../../etc/passwd",
    # os.path.join silently returns the attacker's path.
    full_path = os.path.join(BASE_DIR, user_path)
    with open(full_path, "rb") as f:
        return f.read()


def get_log(log_name):
    """Fetch a log file — same pattern."""
    log_dir = "/var/log/app"
    path = os.path.join(log_dir, log_name)
    # VULNERABLE: log_name = "../../etc/shadow" escapes log_dir
    with open(path) as f:
        return f.read()


if __name__ == "__main__":
    # Attack 1: absolute path override
    try:
        data = download_file("/etc/passwd")
        print(data[:100])
    except OSError as e:
        print(e)

    # Attack 2: relative traversal
    try:
        data = download_file("../../../../etc/hosts")
        print(data[:100])
    except OSError as e:
        print(e)
