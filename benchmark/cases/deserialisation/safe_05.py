# CWE-502: Safe — json.load() from a trusted internal config file
# The file path is a hardcoded constant; user input never influences
# what file is opened or what is deserialised.

import json
from pathlib import Path


CONFIG_PATH = Path("/etc/myapp/config.json")


def load_app_config():
    """
    Load application configuration from a fixed JSON file.
    SAFE: the file path is hardcoded; json.load() cannot execute code.
    """
    with CONFIG_PATH.open("r", encoding="utf-8") as f:
        config = json.load(f)
    return config


def load_feature_flags():
    """Load feature flags from a known JSON file."""
    flags_path = Path("/etc/myapp/feature_flags.json")
    if not flags_path.exists():
        return {}
    with flags_path.open() as f:
        return json.load(f)


def get_db_config():
    """Extract DB connection settings from the app config."""
    config = load_app_config()
    return config.get("database", {})


if __name__ == "__main__":
    try:
        cfg = load_app_config()
        print(f"Config loaded: {list(cfg.keys())}")
    except FileNotFoundError:
        print("Config file not found — using empty config")
        cfg = {}
    print(cfg)
