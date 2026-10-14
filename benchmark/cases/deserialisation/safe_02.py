# CWE-502: Safe — yaml.safe_load() restricts to basic YAML types
# yaml.safe_load() only constructs Python primitives (dict, list, str, int,
# float, bool, None); it cannot instantiate arbitrary Python objects.

import yaml


def parse_config(config_str: str):
    """
    Parse a YAML configuration string.
    SAFE: yaml.safe_load() is restricted to standard YAML types.
    """
    data = yaml.safe_load(config_str)
    return data


def load_user_preferences(raw_yaml: str):
    """Load user preferences — yaml.safe_load is safe for untrusted input."""
    prefs = yaml.safe_load(raw_yaml)
    if not isinstance(prefs, dict):
        return {}
    return prefs


def parse_pipeline(pipeline_yaml: str):
    """Parse a CI/CD pipeline definition."""
    # SAFE: safe_load cannot execute arbitrary Python
    config = yaml.safe_load(pipeline_yaml)
    return config


if __name__ == "__main__":
    sample = """
name: Alice
age: 30
settings:
  theme: dark
  notifications: true
"""
    result = parse_config(sample)
    print(f"Parsed: {result}")

    # A !!python/object attack is blocked by safe_load
    malicious = "!!python/object/apply:os.system ['id']"
    try:
        parse_config(malicious)
    except yaml.YAMLError as exc:
        print(f"Blocked: {exc}")
