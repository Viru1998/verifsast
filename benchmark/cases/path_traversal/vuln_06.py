# CWE-22: Path Traversal (Zip Slip) — zipfile.extract() with user-controlled member
# Vulnerability: extracting a zip entry whose path contains "../" can write files
# outside the destination directory.

import zipfile
import os


EXTRACT_DIR = "/var/www/uploads/extracted"


def extract_archive(zip_path, member_name):
    """
    Extract a specific member from a zip archive.
    VULNERABLE: member_name from user input can be "../../../etc/cron.d/evil"
    """
    os.makedirs(EXTRACT_DIR, exist_ok=True)

    with zipfile.ZipFile(zip_path, "r") as zf:
        # VULNERABLE: extract() does not validate the member path
        zf.extract(member_name, EXTRACT_DIR)

    return os.path.join(EXTRACT_DIR, member_name)


def extract_all_user(zip_path):
    """
    Extract all members from a zip — also vulnerable if archive is attacker-controlled.
    """
    os.makedirs(EXTRACT_DIR, exist_ok=True)

    with zipfile.ZipFile(zip_path, "r") as zf:
        # VULNERABLE: extractall() with no member validation
        zf.extractall(EXTRACT_DIR)

    return EXTRACT_DIR


if __name__ == "__main__":
    # An attacker crafts a zip with member "../../etc/cron.d/backdoor"
    # and calls extract_archive("malicious.zip", "../../etc/cron.d/backdoor")
    try:
        result = extract_archive("archive.zip", "../../etc/passwd")
        print(f"Extracted to: {result}")
    except (KeyError, OSError) as exc:
        print(f"Error: {exc}")
