# CWE-22: Safe — reads from a fixed directory, filename sanitised to alphanum+dot
# After stripping directory components the filename is validated against a
# strict regex that allows only alphanumeric characters, hyphens and a single dot.

import os
import re


UPLOADS_DIR = "/var/www/uploads"

# Allow only safe filenames: letters, digits, hyphens, underscores, and one dot
# Examples: "report-2024.pdf", "image_01.jpg"
SAFE_FILENAME_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,100}\.[a-zA-Z0-9]{1,10}$")


def sanitise_filename(raw_name):
    """Strip directory components and validate the resulting filename."""
    # Remove any directory prefix first
    base = os.path.basename(raw_name)

    if not SAFE_FILENAME_RE.match(base):
        raise ValueError(
            f"Invalid filename {base!r}: only alphanumeric, hyphen, underscore, "
            "and a single dot extension are allowed"
        )
    return base


def read_upload(raw_name):
    """
    Read an uploaded file after sanitising the filename.
    SAFE: only a name matching the strict regex can reach open().
    """
    safe_name = sanitise_filename(raw_name)
    full_path = os.path.join(UPLOADS_DIR, safe_name)
    with open(full_path, "rb") as f:
        return f.read()


if __name__ == "__main__":
    # Legitimate use
    try:
        data = read_upload("report-2024.pdf")
        print(f"Read {len(data)} bytes")
    except OSError as exc:
        print(exc)

    # Traversal blocked by regex
    for attack in ["../../etc/passwd", "../secret.txt", "/etc/hostname", "file;rm.sh"]:
        try:
            read_upload(attack)
        except ValueError as exc:
            print(f"Blocked: {exc}")
