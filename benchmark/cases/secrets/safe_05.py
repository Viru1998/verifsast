# CWE-798: Safe — os.environ.get() with empty string fallback
# Empty string fallback means the app degrades gracefully (e.g. disables a
# feature) rather than leaking a hardcoded secret.  Scanners should not flag "".

import os


# SAFE: empty string default — no secret value in source code
SECRET_KEY   = os.environ.get("SECRET_KEY", "")
DATABASE_URL = os.environ.get("DATABASE_URL", "")
API_KEY      = os.environ.get("THIRD_PARTY_API_KEY", "")


def is_configured():
    """Check whether all required secrets are present."""
    return all([SECRET_KEY, DATABASE_URL, API_KEY])


def get_secret_key():
    """Return the secret key, raising if it is not configured."""
    if not SECRET_KEY:
        raise EnvironmentError("SECRET_KEY environment variable is not set")
    return SECRET_KEY


def make_session_cookie(user_id):
    """Create a signed session cookie — uses the environment secret."""
    import hmac, hashlib
    key = get_secret_key().encode()
    payload = str(user_id).encode()
    sig = hmac.new(key, payload, hashlib.sha256).hexdigest()
    return f"{user_id}.{sig}"


if __name__ == "__main__":
    if is_configured():
        print("All secrets configured")
    else:
        print("One or more secrets are missing from the environment")
