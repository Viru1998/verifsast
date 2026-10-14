# CWE-798: Hardcoded JWT secret
# Vulnerability: the secret used to sign JWTs is a literal string

import hmac
import hashlib
import base64
import json
import time


# VULNERABLE: JWT signing secret is hardcoded
JWT_SECRET = "supersecretjwtkey123"
JWT_ALGORITHM = "HS256"


def base64url_encode(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def create_token(user_id, role):
    """Create a signed JWT — uses hardcoded secret."""
    header  = base64url_encode(json.dumps({"alg": JWT_ALGORITHM, "typ": "JWT"}))
    payload = base64url_encode(json.dumps({
        "sub": user_id,
        "role": role,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }))
    signing_input = f"{header}.{payload}"
    # VULNERABLE: JWT_SECRET is a hardcoded literal
    sig = hmac.new(
        JWT_SECRET.encode(), signing_input.encode(), hashlib.sha256
    ).digest()
    return f"{signing_input}.{base64url_encode(sig)}"


def verify_token(token):
    """Verify a JWT using the hardcoded secret."""
    parts = token.split(".")
    if len(parts) != 3:
        return False
    signing_input = f"{parts[0]}.{parts[1]}"
    expected = hmac.new(
        JWT_SECRET.encode(), signing_input.encode(), hashlib.sha256
    ).digest()
    return base64url_encode(expected) == parts[2]


if __name__ == "__main__":
    tok = create_token(42, "admin")
    print(f"Token: {tok[:40]}...")
    print(f"Valid: {verify_token(tok)}")
