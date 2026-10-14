# CWE-78: Safe — subprocess.run() with list args and no shell=True
# No vulnerability: list form bypasses the shell entirely; each element is
# a discrete argument to execv(), never parsed by /bin/sh.

import subprocess


def ping_host(host):
    """Ping a host — list args prevent shell injection."""
    # SAFE: ["ping", "-c", "2", host] — host is a literal argument, not shell-parsed
    result = subprocess.run(
        ["ping", "-c", "2", host],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout


def list_directory(path):
    """List a directory — list form, no shell."""
    # SAFE: path is passed as a single argument to ls, shell metacharacters are inert
    result = subprocess.run(
        ["ls", "-la", path],
        capture_output=True,
        text=True,
    )
    return result.stdout


def compress_file(filepath, output):
    """Compress a file with gzip — list form."""
    # SAFE: no shell involved
    result = subprocess.run(
        ["gzip", "-k", "-c", filepath],
        capture_output=True,
        timeout=60,
    )
    with open(output, "wb") as f:
        f.write(result.stdout)
    return result.returncode


if __name__ == "__main__":
    # Even with shell metacharacters in the host, nothing is injected
    print(ping_host("8.8.8.8"))
    print(list_directory("/tmp"))
