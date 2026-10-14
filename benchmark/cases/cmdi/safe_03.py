# CWE-78: Safe — shlex.quote() escapes user input before shell use
# Near-miss: shell=True IS used, but shlex.quote() wraps user input so
# special characters are treated as literals by the shell.

import subprocess
import shlex


def search_log(pattern):
    """
    Search a log file for a user-supplied pattern.
    shlex.quote() ensures the pattern is treated as a single, literal argument.
    """
    # SAFE: shlex.quote() wraps the pattern in single quotes, escaping any
    # embedded single quotes, so the shell cannot interpret metacharacters.
    safe_pattern = shlex.quote(pattern)
    cmd = f"grep {safe_pattern} /var/log/app.log"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout


def ping_host(host):
    """Ping with shell=True but quoted host."""
    safe_host = shlex.quote(host)
    result = subprocess.run(
        f"ping -c 2 {safe_host}", shell=True, capture_output=True, text=True, timeout=10
    )
    return result.stdout


def file_info(filepath):
    """Get file information — quoted path."""
    safe_path = shlex.quote(filepath)
    result = subprocess.run(
        f"file {safe_path}", shell=True, capture_output=True, text=True
    )
    return result.stdout


if __name__ == "__main__":
    # Even malicious input is quoted safely
    print(repr(search_log("error; cat /etc/passwd")))
    print(repr(ping_host("8.8.8.8; id")))
