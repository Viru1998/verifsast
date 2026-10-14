# CWE-798: Safe — secrets loaded from .env file via python-dotenv
# The .env file is excluded from version control (.gitignore);
# no secret appears in the Python source.

import os

try:
    from dotenv import load_dotenv
    load_dotenv()  # reads .env into os.environ
except ImportError:
    pass  # python-dotenv not installed; rely on existing env vars


def get_secret(name, required=True):
    """Retrieve a secret from the environment (populated by dotenv)."""
    value = os.environ.get(name)
    if required and not value:
        raise EnvironmentError(f"Required secret {name!r} is not set")
    return value


# All secrets are resolved at import time from the environment
DB_URL     = get_secret("DATABASE_URL")
JWT_SECRET = get_secret("JWT_SECRET")
API_KEY    = get_secret("EXTERNAL_API_KEY")


def get_db_url():
    return DB_URL


def get_jwt_secret():
    return JWT_SECRET


def get_api_key():
    return API_KEY


if __name__ == "__main__":
    print(f"DB URL set: {bool(DB_URL)}")
    print(f"JWT secret set: {bool(JWT_SECRET)}")
    print(f"API key set: {bool(API_KEY)}")
