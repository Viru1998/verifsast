# CWE-502: Safe — yaml.load(data, Loader=yaml.CSafeLoader)
# CSafeLoader is the C-accelerated variant of SafeLoader; same safety
# guarantees, better performance.

import yaml


def load_config(config_data: str):
    """
    Load YAML with the C-accelerated SafeLoader.
    SAFE: yaml.CSafeLoader has the same restrictions as yaml.SafeLoader.
    """
    try:
        # SAFE: CSafeLoader — fast, restricted to standard YAML types
        result = yaml.load(config_data, Loader=yaml.CSafeLoader)
    except AttributeError:
        # Fallback if C extension is not available
        result = yaml.load(config_data, Loader=yaml.SafeLoader)
    return result


def parse_events(events_yaml: str):
    """Parse a list of events from YAML."""
    data = yaml.load(events_yaml, Loader=yaml.CSafeLoader)
    if not isinstance(data, list):
        return []
    return data


def read_schema(schema_yaml: str):
    """Read a validation schema from YAML."""
    return yaml.load(schema_yaml, Loader=yaml.CSafeLoader)


if __name__ == "__main__":
    sample = """
events:
  - name: login
    user: alice
  - name: logout
    user: bob
"""
    config = load_config(sample)
    print(f"Config: {config}")
