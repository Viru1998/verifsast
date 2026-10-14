# CWE-22: Path Traversal — os.listdir() with user-controlled directory
# Vulnerability: attacker can list arbitrary directories

import os


def list_user_files(user_dir):
    """
    List files uploaded by a user.
    VULNERABLE: user_dir is not validated; attacker can pass "../etc" to list
    the system /etc directory.
    """
    # VULNERABLE: os.listdir with raw user input
    try:
        entries = os.listdir(user_dir)
        return entries
    except OSError as exc:
        return []


def get_file_tree(base, subdir):
    """Walk a subdirectory tree — subdir is user-controlled."""
    full = os.path.join(base, subdir)
    # VULNERABLE: no check that full is inside base
    tree = []
    for root, dirs, files in os.walk(full):
        for name in files:
            tree.append(os.path.join(root, name))
    return tree


def count_files(directory):
    """Count files in a directory — directory from user input."""
    # VULNERABLE: directory is user-supplied
    try:
        return len([
            f for f in os.listdir(directory)
            if os.path.isfile(os.path.join(directory, f))
        ])
    except OSError:
        return -1


if __name__ == "__main__":
    # Attacker can enumerate /etc
    files = list_user_files("/etc")
    print("Files in /etc:", files[:10])
    # Enumerate /root
    print(list_user_files("/root"))
