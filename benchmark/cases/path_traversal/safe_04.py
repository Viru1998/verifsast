# CWE-22: Safe — file name selected from a whitelist set
# No traversal is possible because the actual file path is looked up
# from a hardcoded mapping; user input only selects the key.

import os

# Static mapping of public document names to their paths
PUBLIC_FILES = {
    "terms":      "/var/www/docs/terms_of_service.pdf",
    "privacy":    "/var/www/docs/privacy_policy.pdf",
    "faq":        "/var/www/docs/faq.html",
    "changelog":  "/var/www/docs/changelog.txt",
    "readme":     "/var/www/docs/README.md",
}


def serve_document(doc_name):
    """
    Serve a public document by its symbolic name.
    SAFE: doc_name is only used as a key lookup; the actual path comes
          entirely from the hardcoded whitelist.
    """
    if doc_name not in PUBLIC_FILES:
        raise KeyError(
            f"Unknown document: {doc_name!r}. "
            f"Available: {sorted(PUBLIC_FILES)}"
        )

    # The path is from the whitelist, not from user input
    path = PUBLIC_FILES[doc_name]
    with open(path, "rb") as f:
        return f.read()


def list_available():
    """Return the list of available document names."""
    return sorted(PUBLIC_FILES.keys())


if __name__ == "__main__":
    print("Available:", list_available())

    # Traversal attempt — the key simply doesn't exist
    try:
        serve_document("../../etc/passwd")
    except KeyError as exc:
        print(f"Blocked: {exc}")

    # Legitimate use
    try:
        data = serve_document("readme")
        print(f"readme: {len(data)} bytes")
    except OSError as exc:
        print(exc)
