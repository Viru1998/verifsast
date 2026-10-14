# CWE-502: Insecure Deserialisation — marshal.loads() on user bytes
# Vulnerability: marshal deserialises Python bytecode objects; malformed
# marshal data can crash the interpreter or, on some versions, lead to
# code execution.  Bandit flags marshal.loads as B302.

import marshal


def load_bytecode(raw_bytes: bytes):
    """
    Load compiled Python bytecode from bytes.
    VULNERABLE: marshal.loads() on untrusted input — Bandit B302.
    """
    # VULNERABLE: marshal.loads on attacker-controlled bytes
    code_obj = marshal.loads(raw_bytes)
    return code_obj


def deserialise_constants(data: bytes):
    """Deserialise a bundle of Python constants."""
    # VULNERABLE: same concern
    constants = marshal.loads(data)
    return constants


def run_bytecode(raw: bytes):
    """Load and execute marshalled bytecode — double vulnerability."""
    # VULNERABLE: marshal + exec is extremely dangerous
    code = marshal.loads(raw)
    result = {}
    exec(code, result)
    return result


if __name__ == "__main__":
    # Benign round-trip with simple constants
    original = (1, 2, 3, "hello")
    marshalled = marshal.dumps(original)
    restored = load_bytecode(marshalled)
    print(f"Restored: {restored}")
