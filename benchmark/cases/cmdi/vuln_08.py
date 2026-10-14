# CWE-78: OS Command Injection via subprocess.check_output(shell=True)
# Vulnerability: check_output with shell=True and concatenated user pattern

import subprocess


def search_log(pattern):
    """Search a log file for a pattern — check_output + shell=True."""
    # VULNERABLE: pattern is not quoted, injected directly into shell command
    output = subprocess.check_output(
        "grep " + pattern + " /var/log/syslog", shell=True
    )
    return output.decode("utf-8")


def get_file_hash(filepath):
    """Compute SHA-256 hash of a file — injectable filepath."""
    # VULNERABLE: filepath goes into shell command without sanitisation
    output = subprocess.check_output("sha256sum " + filepath, shell=True)
    return output.decode().split()[0]


def list_processes(user):
    """List processes owned by a user — check_output + shell=True."""
    # VULNERABLE: user input in ps command
    out = subprocess.check_output(
        "ps aux | grep " + user, shell=True, stderr=subprocess.DEVNULL
    )
    return out.decode()


if __name__ == "__main__":
    # Attacker: pattern = "error; cat /etc/passwd #"
    try:
        print(search_log("error; cat /etc/passwd #"))
    except subprocess.CalledProcessError as exc:
        print(f"Command failed: {exc}")
