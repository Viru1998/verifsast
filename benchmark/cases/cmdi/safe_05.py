# CWE-78: Safe — subprocess.call() with list args, no shell=True
# The list form means the OS exec() call receives each arg as a distinct
# string; shell metacharacters in any element are inert.

import subprocess


def list_path(path):
    """List directory contents — safe list form."""
    # SAFE: path is a single element in the list, no shell parsing
    ret = subprocess.call(["ls", "-la", path])
    return ret


def copy_file(src, dst):
    """Copy a file safely."""
    # SAFE: cp receives exactly two path arguments
    ret = subprocess.call(["cp", "--preserve=all", src, dst])
    return ret


def set_permissions(path, mode):
    """Set file permissions — mode validated before call."""
    # Extra validation: mode must be an octal string like "755"
    if not mode.isdigit() or len(mode) not in (3, 4):
        raise ValueError(f"Invalid mode: {mode!r}")

    # SAFE: list form, shell never invoked
    ret = subprocess.call(["chmod", mode, path])
    return ret


def make_directory(dirpath):
    """Create a directory tree."""
    # SAFE: list form
    ret = subprocess.call(["mkdir", "-p", dirpath])
    return ret


if __name__ == "__main__":
    list_path("/tmp")
    print(set_permissions("/tmp/testfile", "644"))
