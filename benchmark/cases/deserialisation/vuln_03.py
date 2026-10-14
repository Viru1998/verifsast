# CWE-502: Insecure Deserialisation — yaml.load() without a Loader argument
# Vulnerability: omitting the Loader defaults to yaml.FullLoader in recent PyYAML,
# but older versions default to the unsafe UnsafeLoader; in all cases
# omitting Loader is flagged by Bandit (B506) as potentially unsafe.

import yaml


def parse_config(config_str):
    """
    Parse a YAML configuration string.
    VULNERABLE: yaml.load() without Loader — Bandit B506 flags this.
    """
    # VULNERABLE: no Loader argument
    data = yaml.load(config_str)
    return data


def load_user_preferences(raw_yaml):
    """Load user preferences from YAML submitted via an API."""
    # VULNERABLE: untrusted YAML + no Loader
    prefs = yaml.load(raw_yaml)
    return prefs


def deserialise_message(body):
    """Deserialise a YAML message body from a message queue."""
    # VULNERABLE: yaml.load without Loader on external data
    return yaml.load(body)


if __name__ == "__main__":
    sample = """
name: Alice
age: 30
role: admin
"""
    result = parse_config(sample)
    print(result)
