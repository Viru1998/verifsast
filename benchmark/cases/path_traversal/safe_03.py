# CWE-22: Safe — os.path.basename() strips the directory component
# By taking only the final filename component, ".." and directory separators
# are removed before the path is used.

import os


UPLOAD_DIR = "/var/www/uploads"


def read_file(filename):
    """
    Read a file — only the basename is used, so traversal is impossible.
    SAFE: os.path.basename("../../etc/passwd") returns "passwd";
          the directory cannot be changed.
    """
    safe_name = os.path.basename(filename)

    if not safe_name:
        raise ValueError("Filename must not be empty")

    full_path = os.path.join(UPLOAD_DIR, safe_name)
    with open(full_path, "rb") as f:
        return f.read()


def delete_upload(filename):
    """Delete an uploaded file — basename-only confinement."""
    safe_name = os.path.basename(filename)
    if not safe_name:
        raise ValueError("Empty filename")

    full_path = os.path.join(UPLOAD_DIR, safe_name)
    if os.path.exists(full_path):
        os.unlink(full_path)


def get_upload_path(filename):
    """Return the safe full path for an upload."""
    safe_name = os.path.basename(filename)
    return os.path.join(UPLOAD_DIR, safe_name)


if __name__ == "__main__":
    # "../../etc/passwd" → os.path.basename → "passwd" → /var/www/uploads/passwd
    safe = get_upload_path("../../etc/passwd")
    print(f"Resolved to: {safe}")  # /var/www/uploads/passwd — safe
