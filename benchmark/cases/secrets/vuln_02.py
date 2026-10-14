# CWE-798: Hardcoded API key
# Vulnerability: a real-looking API key is stored as a string literal

import urllib.request
import json


# VULNERABLE: API key hardcoded in source
API_KEY = "sk-abcdef1234567890abcdef1234567890"
BASE_URL = "https://api.example.com/v1"


def call_api(endpoint, payload):
    """Call the example API using the hardcoded key."""
    url = f"{BASE_URL}/{endpoint}"
    data = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": f"Bearer {API_KEY}",   # VULNERABLE
            "Content-Type":  "application/json",
        },
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def get_models():
    """List available models — uses the hardcoded key."""
    return call_api("models", {})


if __name__ == "__main__":
    print(f"Using API key: {API_KEY[:8]}...")
    try:
        models = get_models()
        print(models)
    except Exception as exc:
        print(f"API call failed: {exc}")
