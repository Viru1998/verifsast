# CWE-798: Safe — configuration loaded from an external JSON file
# Secrets are in a config file that is excluded from version control
# (.gitignore), not hardcoded in the Python source.

import json
import os
from pathlib import Path


CONFIG_FILE = Path(os.environ.get("CONFIG_FILE", "/etc/myapp/config.json"))


def load_config():
    """
    Load application configuration from an external JSON file.
    SAFE: secrets are in the file, not in the Python source.
    """
    if not CONFIG_FILE.exists():
        raise FileNotFoundError(
            f"Config file not found: {CONFIG_FILE}. "
            "Copy config.example.json to the path and fill in values."
        )
    with CONFIG_FILE.open() as f:
        config = json.load(f)
    return config


_config = None


def get_config():
    """Return a cached copy of the loaded config."""
    global _config
    if _config is None:
        _config = load_config()
    return _config


def get_db_password():
    return get_config()["database"]["password"]


def get_api_key():
    return get_config()["api"]["key"]


def get_smtp_password():
    return get_config()["smtp"]["password"]


if __name__ == "__main__":
    try:
        cfg = get_config()
        print(f"Config loaded — keys: {list(cfg.keys())}")
    except FileNotFoundError as exc:
        print(exc)
