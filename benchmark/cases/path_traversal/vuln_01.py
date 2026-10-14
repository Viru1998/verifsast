# CWE-22: Path Traversal — open() called directly with user-supplied filename
# Vulnerability: no sanitisation before opening the file

import os


def serve_file(filename):
    """
    Return the contents of a file from the uploads directory.
    Vulnerable: filename is used directly in open() without validation.
    """
    # VULNERABLE: open() with raw user input; attacker can pass "../../etc/passwd"
    try:
        with open(filename, "r") as f:
            return f.read()
    except FileNotFoundError:
        return None
    except PermissionError:
        return None


def get_template(template_name):
    """Load a template file by name — also vulnerable."""
    # VULNERABLE: template_name could escape the templates directory
    base = "/app/templates/"
    try:
        with open(base + template_name) as f:
            return f.read()
    except OSError:
        return ""


def read_config(config_file):
    """Read a named config file — direct open()."""
    # VULNERABLE: config_file is user-controlled
    with open(config_file, "rb") as f:
        return f.read()


if __name__ == "__main__":
    # Attacker traversal: ../../etc/passwd
    content = serve_file("../../etc/passwd")
    print(content[:200] if content else "File not found")
