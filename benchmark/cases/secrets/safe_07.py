# CWE-798: Near-miss — placeholder string "change-me-in-production"
# The value is explicitly a placeholder; Bandit may flag this for review,
# but it is not a real secret.  Tests whether the classifier distinguishes
# placeholder patterns from actual credentials.

import os
import warnings


# Near-miss: placeholder value that should be overridden in production.
# Scanners may flag this because it contains a "secret"-like variable name.
SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-in-production")

# Another common placeholder pattern
JWT_SECRET = os.environ.get("JWT_SECRET", "REPLACE_ME")


def _warn_if_placeholder(name, value):
    """Emit a warning if the value is still a well-known placeholder."""
    placeholders = {"change-me-in-production", "REPLACE_ME", "todo", "fixme", ""}
    if value.lower() in {p.lower() for p in placeholders}:
        warnings.warn(
            f"{name} is still set to a placeholder value. "
            "Set a real secret before deploying.",
            UserWarning,
            stacklevel=2,
        )


_warn_if_placeholder("SECRET_KEY", SECRET_KEY)
_warn_if_placeholder("JWT_SECRET", JWT_SECRET)


def get_secret_key():
    _warn_if_placeholder("SECRET_KEY", SECRET_KEY)
    return SECRET_KEY


if __name__ == "__main__":
    print(f"SECRET_KEY = {get_secret_key()!r}")
