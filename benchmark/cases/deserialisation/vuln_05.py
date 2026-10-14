# CWE-502: Insecure Deserialisation — yaml.load(data, Loader=yaml.UnsafeLoader)
# Vulnerability: yaml.UnsafeLoader is explicitly the most dangerous loader;
# it allows full Python object instantiation from YAML tags.

import yaml


def load_data(raw):
    """
    Load YAML data with the explicitly unsafe loader.
    VULNERABLE: UnsafeLoader is documented as unsafe for untrusted input.
    """
    # VULNERABLE: yaml.UnsafeLoader
    return yaml.load(raw, Loader=yaml.UnsafeLoader)


def restore_object(yaml_str):
    """Restore a Python object from its YAML representation."""
    # VULNERABLE: can deserialise arbitrary objects
    obj = yaml.load(yaml_str, Loader=yaml.UnsafeLoader)
    return obj


def parse_template(template_str):
    """Parse a Jinja2-like template definition stored in YAML."""
    # VULNERABLE: same unsafe loader
    return yaml.load(template_str, Loader=yaml.UnsafeLoader)


if __name__ == "__main__":
    safe_yaml = "name: test\nvalue: 42"
    result = load_data(safe_yaml)
    print(result)

    # A malicious YAML would be:
    # "!!python/object/apply:os.system ['id']"
    # load_data(malicious_yaml)  # would execute 'id'
