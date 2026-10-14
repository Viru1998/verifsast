# CWE-502: Safe — configparser.ConfigParser() for INI-format configuration
# ConfigParser only parses key=value pairs in sections; no code execution.

import configparser
import io


def load_ini_config(config_str: str):
    """
    Parse an INI-format configuration string.
    SAFE: configparser cannot execute code; it only extracts string values.
    """
    parser = configparser.ConfigParser()
    # read_string accepts a string (not a filename)
    parser.read_string(config_str)
    return parser


def get_db_config(config_str: str):
    """Extract database settings from an INI config."""
    parser = load_ini_config(config_str)
    if "database" not in parser:
        return {}
    return dict(parser["database"])


def get_all_sections(config_str: str):
    """Return all section names from an INI config."""
    parser = load_ini_config(config_str)
    return parser.sections()


def merge_configs(*config_strings):
    """Merge multiple INI configs — later strings override earlier ones."""
    parser = configparser.ConfigParser()
    for s in config_strings:
        parser.read_string(s)
    result = {}
    for section in parser.sections():
        result[section] = dict(parser[section])
    return result


if __name__ == "__main__":
    sample_ini = """
[database]
host = localhost
port = 5432
name = myapp
user = appuser

[server]
host = 0.0.0.0
port = 8080
"""
    db = get_db_config(sample_ini)
    print(f"DB config: {db}")
    print(f"Sections: {get_all_sections(sample_ini)}")
