# CWE-502: Safe — tomllib.loads() for configuration (Python 3.11+)
# TOML is a data-only format; there is no mechanism for executing code
# during parsing.

import sys


def load_toml_config(config_str: str):
    """
    Load a TOML configuration string.
    SAFE: TOML only supports primitive data types; no code execution is possible.
    """
    if sys.version_info >= (3, 11):
        import tomllib
        data = tomllib.loads(config_str)
    else:
        try:
            import tomli as tomllib  # pip install tomli for < 3.11
            data = tomllib.loads(config_str)
        except ImportError:
            raise ImportError(
                "tomli required for Python < 3.11: pip install tomli"
            )
    return data


def get_db_config(toml_str: str):
    """Extract the [database] section from TOML config."""
    config = load_toml_config(toml_str)
    return config.get("database", {})


def get_server_config(toml_str: str):
    """Extract the [server] section."""
    config = load_toml_config(toml_str)
    return config.get("server", {})


if __name__ == "__main__":
    sample_toml = """
[database]
host = "localhost"
port = 5432
name = "myapp"

[server]
host = "0.0.0.0"
port = 8080
debug = false
"""
    try:
        config = load_toml_config(sample_toml)
        print(f"DB: {config.get('database')}")
        print(f"Server: {config.get('server')}")
    except ImportError as exc:
        print(exc)
