# CWE-22: Safe — zipfile.extract() with member validation (no "..")
# Each member name is checked before extraction to prevent zip slip.

import zipfile
import os
import pathlib


EXTRACT_DIR = "/var/www/uploads/extracted"


def is_safe_member(member_name, extract_dir):
    """
    Return True if the member, once extracted, would be inside extract_dir.
    Rejects members with absolute paths, ".." components, or Windows drive specs.
    """
    if os.path.isabs(member_name):
        return False

    # Reject any ".." component
    parts = pathlib.PurePosixPath(member_name).parts
    if ".." in parts:
        return False

    # Confirm the resolved path stays inside extract_dir
    target = pathlib.Path(extract_dir, member_name).resolve()
    base   = pathlib.Path(extract_dir).resolve()
    return target.is_relative_to(base)


def extract_archive(zip_path):
    """Extract a zip archive safely — every member is validated first."""
    os.makedirs(EXTRACT_DIR, exist_ok=True)
    extracted = []

    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            if not is_safe_member(info.filename, EXTRACT_DIR):
                print(f"Skipping unsafe member: {info.filename!r}")
                continue

            zf.extract(info, EXTRACT_DIR)
            extracted.append(info.filename)

    return extracted


if __name__ == "__main__":
    try:
        members = extract_archive("archive.zip")
        print(f"Extracted {len(members)} file(s)")
    except (zipfile.BadZipFile, OSError) as exc:
        print(f"Error: {exc}")
