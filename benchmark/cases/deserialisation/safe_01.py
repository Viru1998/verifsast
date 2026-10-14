# CWE-502: Safe — json.loads() for user-supplied data
# JSON deserialisation cannot execute arbitrary code; it only produces
# dicts, lists, strings, numbers, booleans, and None.

import json


def parse_request_body(body: str):
    """
    Parse a JSON request body.
    SAFE: json.loads() cannot instantiate Python objects or execute code.
    """
    try:
        data = json.loads(body)
        return data
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON: {exc}") from exc


def load_config(config_str: str):
    """Load configuration from a JSON string — safe for untrusted input."""
    config = json.loads(config_str)

    # Basic type validation after parsing
    if not isinstance(config, dict):
        raise TypeError("Config must be a JSON object")
    return config


def deserialise_message(payload: str):
    """Deserialise a message from a queue — JSON is safe."""
    msg = json.loads(payload)
    required_keys = {"type", "data", "timestamp"}
    if not required_keys.issubset(msg.keys()):
        raise ValueError(f"Message missing required keys: {required_keys - msg.keys()}")
    return msg


if __name__ == "__main__":
    result = parse_request_body('{"user": "alice", "role": "admin"}')
    print(f"Parsed: {result}")

    # Even with a malicious-looking string, json.loads is safe
    try:
        parse_request_body('{"exploit": "__import__(os).system(id)"}')
        print("JSON parsed safely — no code executed")
    except Exception as exc:
        print(exc)
