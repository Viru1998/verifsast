# CWE-502: Insecure Deserialisation — yaml.load(data, Loader=yaml.Loader)
# Vulnerability: yaml.Loader (capital L) is the full, unsafe loader that can
# instantiate arbitrary Python objects via !!python/object tags.

import yaml


def load_config(config_data):
    """
    Load configuration — uses the unsafe yaml.Loader.
    VULNERABLE: yaml.Loader allows arbitrary object construction.
    Attack payload: "!!python/object/apply:os.system ['id']"
    """
    # VULNERABLE: yaml.Loader is unsafe
    result = yaml.load(config_data, Loader=yaml.Loader)
    return result


def parse_pipeline(pipeline_yaml):
    """Parse a CI/CD pipeline definition — also uses yaml.Loader."""
    # VULNERABLE
    return yaml.load(pipeline_yaml, Loader=yaml.Loader)


def read_manifest(manifest_content):
    """Read a deployment manifest."""
    # VULNERABLE: same unsafe Loader
    return yaml.load(manifest_content, Loader=yaml.Loader)


if __name__ == "__main__":
    config = """
database:
  host: localhost
  port: 5432
"""
    print(load_config(config))
