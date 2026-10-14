# CWE-798: Hardcoded private key (PEM string)
# Vulnerability: an RSA private key embedded as a string literal

import base64


# VULNERABLE: RSA private key hardcoded in source
# (truncated for brevity but pattern is clear to scanners)
PRIVATE_KEY_PEM = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLzHPZe5UJr7/LmTFdRE8t4zBhUMsgGiSHgj7ozf
EffhBhvGGpY+n8j2wlPziVWbG4GmEMQYSViFuGkfyQRRKBE4NxNrBGEIUFCo3A32
4lnX/Xf/HxQmbSVeJEKZDWVSzFDwNeWHFNGAzWS1bUyO/7Ww2YcBbq00dTBd3xw3
I4oM4fRg6rl8Ev73bflG0e9bMR5f3FKNQKxbJ5Gt/EXAMPLEEXAMPLEEXAMPLEKEY0
9ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890AB
CDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
-----END RSA PRIVATE KEY-----"""


def load_private_key():
    """Return the hardcoded private key for signing operations."""
    # VULNERABLE: returns the hardcoded PEM string
    return PRIVATE_KEY_PEM


def sign_data(data: bytes) -> bytes:
    """Stub: sign data with the hardcoded key."""
    # In a real implementation this would use cryptography or ssl libs
    key = load_private_key()
    # Simplified stub — shows the key is used
    return base64.b64encode(data)


if __name__ == "__main__":
    key = load_private_key()
    print(f"Key starts with: {key.strip()[:30]}...")
    print(f"Key length: {len(key)} chars")
