# CWE-22: Safe — only .txt extension allowed + basename stripping
# Double mitigation: strip directory component, then enforce extension.

import os


DOCS_DIR = "/var/www/docs"
ALLOWED_EXTENSION = ".txt"


def read_document(filename):
    """
    Read a text document from DOCS_DIR.
    SAFE: basename() removes directory components;
          extension check ensures only .txt files are served.
    """
    # Step 1: strip any directory prefix
    safe_name = os.path.basename(filename)

    if not safe_name:
        raise ValueError("Filename is empty")

    # Step 2: enforce allowed extension
    _, ext = os.path.splitext(safe_name)
    if ext.lower() != ALLOWED_EXTENSION:
        raise ValueError(
            f"Only {ALLOWED_EXTENSION} files are allowed; got {ext!r}"
        )

    full_path = os.path.join(DOCS_DIR, safe_name)
    with open(full_path, "r", encoding="utf-8") as f:
        return f.read()


def list_text_files():
    """List all .txt files in DOCS_DIR."""
    return [
        f for f in os.listdir(DOCS_DIR)
        if f.endswith(ALLOWED_EXTENSION)
    ]


if __name__ == "__main__":
    # Traversal blocked by basename
    try:
        read_document("../../etc/passwd")
    except ValueError as exc:
        print(f"Blocked (extension): {exc}")
    except OSError as exc:
        print(f"File not found: {exc}")

    # Wrong extension blocked
    try:
        read_document("config.php")
    except ValueError as exc:
        print(f"Blocked (extension): {exc}")

    print("Available:", list_text_files())
