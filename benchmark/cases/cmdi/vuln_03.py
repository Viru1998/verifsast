# CWE-78: OS Command Injection via subprocess.run with f-string and shell=True
# Vulnerability: f-string builds the command, shell=True executes it

import subprocess


def ping_host(host):
    """Ping a host — f-string + shell=True is exploitable."""
    # VULNERABLE: host from user input embedded in f-string, then shell=True
    result = subprocess.run(f"ping -c 2 {host}", shell=True, capture_output=True, text=True)
    return result.stdout


def nslookup(domain):
    """DNS lookup via nslookup — also vulnerable."""
    result = subprocess.run(
        f"nslookup {domain}", shell=True, capture_output=True, text=True
    )
    return result.stdout


def traceroute(target):
    """Traceroute to target — f-string shell command."""
    result = subprocess.run(
        f"traceroute {target}", shell=True, capture_output=True, text=True, timeout=30
    )
    return result.stdout


if __name__ == "__main__":
    # Attacker: host = "8.8.8.8; whoami"
    output = ping_host("8.8.8.8; whoami")
    print(output)
