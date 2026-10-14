# CWE-22: Safe — tarfile safe extract with member validation (no ".." / absolute)
# Validates every member before extraction to prevent tar slip attacks.

import tarfile
import os
import pathlib


EXTRACT_DIR = "/tmp/safe_extract"


def is_safe_tar_member(member):
    """
    Return True if the tar member is safe to extract:
    - No absolute path
    - No ".." path component
    - No hardlinks pointing outside (linkname check)
    """
    # Reject absolute paths
    if os.path.isabs(member.name):
        return False

    # Reject any ".." component
    parts = pathlib.PurePosixPath(member.name).parts
    if ".." in parts:
        return False

    # Reject hardlinks / symlinks whose target escapes (basic check)
    if member.islnk() or member.issym():
        if os.path.isabs(member.linkname) or ".." in member.linkname:
            return False

    return True


def safe_extract_tar(tar_path):
    """Extract a tarball, skipping any unsafe members."""
    os.makedirs(EXTRACT_DIR, exist_ok=True)
    extracted = []
    skipped = []

    with tarfile.open(tar_path, "r:*") as tf:
        for member in tf.getmembers():
            if not is_safe_tar_member(member):
                skipped.append(member.name)
                print(f"Skipping unsafe member: {member.name!r}")
                continue

            tf.extract(member, EXTRACT_DIR)
            extracted.append(member.name)

    return extracted, skipped


if __name__ == "__main__":
    try:
        good, bad = safe_extract_tar("archive.tar.gz")
        print(f"Extracted {len(good)}, skipped {len(bad)}")
    except (tarfile.TarError, OSError) as exc:
        print(f"Error: {exc}")
