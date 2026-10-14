# CWE-502: Insecure Deserialisation — pickle.loads() on user-supplied bytes
# Vulnerability: pickle can execute arbitrary Python code during deserialisation

import pickle
import base64


def load_user_session(session_data: bytes):
    """
    Restore a user session from serialised bytes.
    VULNERABLE: if session_data comes from an attacker, pickle executes
                any __reduce__ payload embedded in the data.
    """
    # VULNERABLE: unpickling untrusted data is RCE
    session = pickle.loads(session_data)
    return session


def deserialise_object(raw_bytes: bytes):
    """Generic object deserialisation — also vulnerable."""
    # VULNERABLE
    return pickle.loads(raw_bytes)


def handle_cache_entry(cache_value: bytes):
    """Read an object from a cache backend — cache value is attacker-influenced."""
    # VULNERABLE: cache poisoning leads to RCE via pickle
    obj = pickle.loads(cache_value)
    return obj


if __name__ == "__main__":
    # Demonstrate a benign round-trip (safe data)
    data = {"user_id": 42, "role": "user"}
    serialised = pickle.dumps(data)
    restored = load_user_session(serialised)
    print(f"Restored: {restored}")

    # A malicious payload would look like:
    # class Exploit: __reduce__ = lambda self: (__import__('os').system, ('id',))
    # evil = pickle.dumps(Exploit())
    # load_user_session(evil)  # executes 'id'
