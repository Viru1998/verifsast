# CWE-22: Path Traversal — string concatenation to build file path
# Vulnerability: base_dir + "/" + filename allows "../" sequences to escape

import os


BASE_DIR = "/srv/files"


def read_document(filename):
    """Read a document from the files store — concat is exploitable."""
    # VULNERABLE: simple string concatenation; filename can include "../"
    path = BASE_DIR + "/" + filename
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def write_report(report_name, content):
    """Write a report — also uses concatenation."""
    path = "/var/reports" + "/" + report_name
    # VULNERABLE: report_name = "../../etc/motd" overwrites system file
    with open(path, "w") as f:
        f.write(content)


def delete_file(category, filename):
    """Delete a file from a category subdirectory."""
    # VULNERABLE: double concat with two user-controlled components
    full_path = "/srv/data/" + category + "/" + filename
    os.unlink(full_path)


if __name__ == "__main__":
    try:
        print(read_document("../../etc/hostname"))
    except OSError as exc:
        print(f"Error: {exc}")
