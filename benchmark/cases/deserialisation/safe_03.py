# CWE-502: Safe — yaml.load(data, Loader=yaml.SafeLoader)
# Explicit SafeLoader is equivalent to yaml.safe_load(); this form is
# recognised by scanners as safe (unlike yaml.Loader or yaml.UnsafeLoader).

import yaml


def load_config(config_data: str):
    """
    Load YAML config with the explicit SafeLoader.
    SAFE: yaml.SafeLoader restricts construction to built-in types.
    """
    # SAFE: Loader=yaml.SafeLoader
    result = yaml.load(config_data, Loader=yaml.SafeLoader)
    return result


def parse_manifest(manifest_content: str):
    """Parse a deployment manifest with SafeLoader."""
    # SAFE
    return yaml.load(manifest_content, Loader=yaml.SafeLoader)


def read_schema(schema_str: str):
    """Read a JSON Schema stored in YAML format."""
    # SAFE: SafeLoader
    schema = yaml.load(schema_str, Loader=yaml.SafeLoader)
    if not isinstance(schema, dict):
        raise ValueError("Schema must be a YAML mapping")
    return schema


if __name__ == "__main__":
    yaml_input = """
server:
  host: localhost
  port: 8080
features:
  - auth
  - logging
"""
    config = load_config(yaml_input)
    print(f"Config: {config}")
