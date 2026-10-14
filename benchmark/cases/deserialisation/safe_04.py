# CWE-502: Safe — pickle.loads() on hardcoded/trusted internal bytes only
# Near-miss: pickle IS used, but only on data that is a compile-time constant
# (never on user input).  The scanner may still flag the call, but the
# actual risk is zero because an attacker cannot influence the bytes.

import pickle


# Hardcoded pickle bytes generated once from trusted data and checked in.
# These bytes represent {"version": 1, "defaults": {"timeout": 30}}
_TRUSTED_DEFAULTS_BYTES = pickle.dumps({"version": 1, "defaults": {"timeout": 30}})


def load_defaults():
    """
    Load hard-coded application defaults from a trusted pickle blob.
    SAFE: _TRUSTED_DEFAULTS_BYTES is a literal constant defined in this file,
          not sourced from user input, the network, or the filesystem.
    """
    # SAFE (near-miss): bytes are a hardcoded constant, not user-supplied
    return pickle.loads(_TRUSTED_DEFAULTS_BYTES)


def get_default_timeout():
    """Return the default timeout from the trusted defaults blob."""
    defaults = load_defaults()
    return defaults["defaults"]["timeout"]


if __name__ == "__main__":
    defaults = load_defaults()
    print(f"Defaults: {defaults}")
    print(f"Timeout: {get_default_timeout()}")
