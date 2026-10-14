# CWE-78: Safe — subprocess.run() with shlex.split()
# Near-miss: shlex.split() splits a command string safely, respecting quoting,
# so it is significantly safer than passing a raw string with shell=True.

import subprocess
import shlex


def run_command(cmd_template, user_value):
    """
    Run a command where one value is user-controlled.
    shlex.split parses the template; the user value is appended as a
    separate element so the shell never sees it.
    """
    # SAFE: shlex.split breaks the template into tokens, user_value is
    # appended as a single list element — not re-parsed by a shell
    args = shlex.split(cmd_template) + [user_value]
    result = subprocess.run(args, capture_output=True, text=True, timeout=15)
    return result.stdout


def grep_file(pattern, filepath):
    """Grep a log file — both args split safely."""
    # SAFE: shlex.split + list append; shell=False (default)
    base = shlex.split("grep -n -i")
    result = subprocess.run(base + [pattern, filepath], capture_output=True, text=True)
    return result.stdout


def convert_image(src, dst, size):
    """ImageMagick conversion — args via shlex and list."""
    base_cmd = shlex.split(f"convert -resize {shlex.quote(size)}")
    result = subprocess.run(base_cmd + [src, dst], capture_output=True, text=True)
    return result.returncode


if __name__ == "__main__":
    output = run_command("echo", "hello; id")  # 'id' is NOT executed
    print(repr(output))
