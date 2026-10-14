# CWE-22: Path Traversal — reads file from URL-decoded path parameter
# Vulnerability: URL-encoded traversal sequences are decoded before use

import urllib.parse
import os


DOCUMENT_ROOT = "/var/www/public"


def serve_document(raw_path):
    """
    Serve a document after URL-decoding the path.
    VULNERABLE: URL decoding converts %2e%2e%2f into "../" allowing traversal.
    """
    # Decode URL encoding — an attacker sends %2e%2e%2fetc%2fpasswd
    decoded_path = urllib.parse.unquote(raw_path)

    full_path = os.path.join(DOCUMENT_ROOT, decoded_path)
    # VULNERABLE: no realpath check after decoding
    with open(full_path, "rb") as f:
        return f.read()


def handle_request(request_path):
    """
    Simulate handling of an HTTP path.
    Double-decode vulnerability: decode twice to bypass single-decode filters.
    """
    # First decode
    once = urllib.parse.unquote(request_path)
    # VULNERABLE: a single filter on 'once' can be bypassed with double-encoding;
    # here we decode a second time before opening the file
    twice = urllib.parse.unquote(once)

    full = DOCUMENT_ROOT + "/" + twice
    try:
        with open(full) as f:
            return f.read()
    except OSError:
        return None


if __name__ == "__main__":
    # URL-encoded traversal: %2e%2e%2f%2e%2e%2fetc%2fpasswd
    result = serve_document("%2e%2e%2f%2e%2e%2fetc%2fpasswd")
    if result:
        print(result[:100])
