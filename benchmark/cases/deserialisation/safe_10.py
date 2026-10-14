# CWE-502: Safe — pickle.loads() with HMAC signature verification before deserialising
# Near-miss: pickle IS used, but only after verifying a MAC that proves the
# data was produced by this application and has not been tampered with.
# An attacker who cannot forge the MAC cannot inject a malicious pickle payload.

import pickle
import hmac
import hashlib
import os
import struct

# Secret key used to sign pickle payloads — loaded from environment
_SIGNING_KEY = os.environ.get("PICKLE_SIGNING_KEY", "").encode()


def sign(data: bytes) -> bytes:
    """Produce a 32-byte HMAC-SHA256 signature over data."""
    if not _SIGNING_KEY:
        raise EnvironmentError("PICKLE_SIGNING_KEY must be set")
    return hmac.new(_SIGNING_KEY, data, hashlib.sha256).digest()


def dumps_signed(obj) -> bytes:
    """Serialise obj with pickle and prepend an HMAC signature."""
    payload = pickle.dumps(obj)
    mac = sign(payload)
    # Format: <32-byte MAC> <pickle payload>
    return mac + payload


def loads_signed(signed_data: bytes):
    """
    Verify the HMAC signature, then deserialise.
    SAFE: if the signature is invalid (tampered data), raises ValueError
          before pickle.loads() is ever called.
    """
    if len(signed_data) < 32:
        raise ValueError("Signed data too short")

    mac     = signed_data[:32]
    payload = signed_data[32:]

    expected = sign(payload)
    if not hmac.compare_digest(mac, expected):
        raise ValueError("MAC verification failed — data has been tampered with")

    # SAFE: only reaches here if the MAC is valid (data is trusted)
    return pickle.loads(payload)


if __name__ == "__main__":
    import os
    os.environ["PICKLE_SIGNING_KEY"] = "demo-key-replace-in-prod"

    # Re-import to pick up the env var
    _SIGNING_KEY = os.environ["PICKLE_SIGNING_KEY"].encode()

    data = {"user_id": 42, "role": "admin"}
    signed = dumps_signed(data)
    restored = loads_signed(signed)
    print(f"Restored: {restored}")

    # Tampered data is rejected
    tampered = signed[:32] + b"\x00" * (len(signed) - 32)
    try:
        loads_signed(tampered)
    except ValueError as exc:
        print(f"Tampered data rejected: {exc}")
