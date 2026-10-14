# CWE-78: Safe — pathlib.Path operations instead of shell commands
# File system operations performed via Python's stdlib — no shell invoked.

import pathlib
import shutil
import stat


def list_directory(directory):
    """List files in a directory — pure Python, no shell."""
    # SAFE: pathlib.Path.iterdir() is a Python API call, not a shell command
    base = pathlib.Path(directory)
    if not base.is_dir():
        raise NotADirectoryError(f"Not a directory: {directory}")

    entries = []
    for entry in sorted(base.iterdir()):
        info = entry.stat()
        entries.append({
            "name":  entry.name,
            "size":  info.st_size,
            "is_dir": entry.is_dir(),
        })
    return entries


def copy_file(src, dst):
    """Copy a file using shutil — no shell."""
    # SAFE: shutil.copy2 is a Python stdlib function
    shutil.copy2(src, dst)


def set_permissions(path, mode_octal):
    """Set permissions using os.chmod — no shell."""
    # SAFE: Python stdlib chmod, mode must be a valid octal int
    p = pathlib.Path(path)
    p.chmod(mode_octal)


def remove_tree(directory):
    """Remove a directory tree — shutil, no shell."""
    # SAFE: shutil.rmtree, no shell
    shutil.rmtree(directory)


def read_file_lines(filepath):
    """Read file lines — no shell cat/tail needed."""
    return pathlib.Path(filepath).read_text(encoding="utf-8").splitlines()


if __name__ == "__main__":
    entries = list_directory("/tmp")
    for e in entries[:5]:
        print(e)
