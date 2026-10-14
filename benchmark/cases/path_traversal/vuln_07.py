# CWE-22: Path Traversal — tarfile extraction with user-controlled member
# Vulnerability: tarfile members can have absolute paths or "../" sequences
# which escape the extraction directory.

import tarfile
import os


EXTRACT_DIR = "/tmp/extracted"


def extract_tar_member(tar_path, member_name):
    """Extract a named member from a tarball — member_name is user-controlled."""
    os.makedirs(EXTRACT_DIR, exist_ok=True)

    with tarfile.open(tar_path, "r:gz") as tf:
        # VULNERABLE: extract() does not sanitise member_name;
        # a crafted tar can contain members like "../../etc/passwd"
        tf.extract(member_name, path=EXTRACT_DIR)

    return os.path.join(EXTRACT_DIR, member_name)


def extract_tar_all(tar_path):
    """Extract an entire tarball without member validation."""
    os.makedirs(EXTRACT_DIR, exist_ok=True)

    with tarfile.open(tar_path, "r:*") as tf:
        # VULNERABLE: extractall() with no filter — Python 3.12 warns but does not block
        tf.extractall(path=EXTRACT_DIR)

    return EXTRACT_DIR


def list_tar_contents(tar_path):
    """List the names of all members in a tarball."""
    with tarfile.open(tar_path, "r:*") as tf:
        return tf.getnames()


if __name__ == "__main__":
    members = list_tar_contents("archive.tar.gz")
    print("Members:", members)
    try:
        extract_tar_all("archive.tar.gz")
    except OSError as exc:
        print(f"Error: {exc}")
