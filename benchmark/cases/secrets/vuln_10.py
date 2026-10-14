# CWE-798: Hardcoded Django secret key
# Vulnerability: SECRET_KEY is a well-known Django config value embedded as a literal

from functools import wraps
import hmac
import hashlib


# VULNERABLE: Django-style secret key hardcoded
SECRET_KEY = "django-insecure-hardcoded-value-here"

# Other hardcoded secrets in the same file
DEBUG = True
ALLOWED_HOSTS = ["*"]

DATABASES = {
    "default": {
        "ENGINE":   "django.db.backends.postgresql",
        "NAME":     "mydb",
        "USER":     "myuser",
        "PASSWORD": "mydbpassword",   # VULNERABLE: second hardcoded secret
        "HOST":     "localhost",
        "PORT":     "5432",
    }
}


def make_csrf_token(session_id):
    """Generate a CSRF token signed with the hardcoded SECRET_KEY."""
    # VULNERABLE: secret used in HMAC is hardcoded
    return hmac.new(
        SECRET_KEY.encode(), session_id.encode(), hashlib.sha256
    ).hexdigest()


def verify_csrf(session_id, token):
    """Verify a CSRF token."""
    expected = make_csrf_token(session_id)
    return hmac.compare_digest(expected, token)


if __name__ == "__main__":
    print(f"SECRET_KEY: {SECRET_KEY}")
    token = make_csrf_token("user-session-abc")
    print(f"CSRF token: {token[:20]}...")
