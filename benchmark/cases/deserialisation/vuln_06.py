# CWE-502: Insecure Deserialisation — cPickle.loads() (Python 2 / compat shim)
# Vulnerability: cPickle is the C-accelerated pickle; same RCE risk.

try:
    import cPickle as pickle_module  # Python 2
except ImportError:
    import pickle as pickle_module   # Python 3 fallback


def load_session(session_bytes: bytes):
    """
    Deserialise a session using cPickle.
    VULNERABLE: cPickle.loads() / pickle.loads() on untrusted data.
    """
    # VULNERABLE: cPickle.loads with user-controlled bytes
    session = pickle_module.loads(session_bytes)
    return session


def load_cached_result(raw: bytes):
    """Load a result object from the cache store."""
    # VULNERABLE: attacker can poison the cache
    return pickle_module.loads(raw)


def load_queue_message(msg_body: bytes):
    """Deserialise a message from a task queue."""
    # VULNERABLE: message contents are user-influenced
    task = pickle_module.loads(msg_body)
    return task


if __name__ == "__main__":
    import pickle
    data = {"task": "process", "user_id": 1}
    raw = pickle.dumps(data)
    result = load_session(raw)
    print(f"Loaded: {result}")
