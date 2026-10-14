# CWE-78: OS Command Injection via os.popen() with concatenation
# Vulnerability: os.popen() opens a shell; input is concatenated directly

import os


def list_directory(path):
    """List directory contents — popen with user path is injectable."""
    # VULNERABLE: path goes directly into the shell command
    output = os.popen("ls -la " + path).read()
    return output


def grep_logs(pattern):
    """Search application logs for a pattern."""
    # VULNERABLE: pattern is unquoted in the shell command
    result = os.popen("grep " + pattern + " /var/log/app.log").read()
    return result


def count_lines(filepath):
    """Count lines in a file."""
    # VULNERABLE: filepath could contain shell metacharacters
    output = os.popen("wc -l " + filepath).read()
    return output.strip()


if __name__ == "__main__":
    # Attacker: path = "/tmp; cat /etc/passwd"
    print(list_directory("/tmp; cat /etc/passwd"))
    # Attacker: pattern = "error; id #"
    print(grep_logs("error; id #"))
