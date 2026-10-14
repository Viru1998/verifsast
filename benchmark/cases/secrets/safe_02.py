# CWE-798: Safe — API key loaded with os.getenv() and explicit error on missing
# getenv() returns None if the variable is absent; the explicit check ensures
# the application does not continue with an empty/None key.

import os
import sys


def get_api_key():
    """
    Load the API key from the environment.
    Raises EnvironmentError if the variable is not set.
    """
    api_key = os.getenv("API_KEY")
    if not api_key:
        raise EnvironmentError(
            "API_KEY environment variable is not set. "
            "Set it before starting the application."
        )
    return api_key


def call_api(endpoint, payload):
    """Make an API call using the environment-sourced key."""
    import urllib.request, json

    api_key = get_api_key()   # SAFE: raises if not set; never a hardcoded default
    req = urllib.request.Request(
        f"https://api.example.com/{endpoint}",
        data=json.dumps(payload).encode(),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type":  "application/json",
        },
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


if __name__ == "__main__":
    try:
        key = get_api_key()
        print(f"Key loaded ({len(key)} chars)")
    except EnvironmentError as exc:
        print(exc)
        sys.exit(1)
