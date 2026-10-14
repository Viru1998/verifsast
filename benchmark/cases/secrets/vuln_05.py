# CWE-798: Hardcoded database URL with credentials
# Vulnerability: full connection string with username and password in source

import urllib.parse


# VULNERABLE: credentials are part of a hardcoded connection URL
DATABASE_URL = "postgresql://admin:p@ssw0rd@db.example.com/prod"


def parse_db_url(url):
    """Parse a database URL into its components."""
    parsed = urllib.parse.urlparse(url)
    return {
        "scheme":   parsed.scheme,
        "host":     parsed.hostname,
        "port":     parsed.port or 5432,
        "database": parsed.path.lstrip("/"),
        "username": parsed.username,
        "password": parsed.password,   # exposed in the dict
    }


def get_db_config():
    """Return DB configuration — exposes the hardcoded password."""
    return parse_db_url(DATABASE_URL)


def build_connection_string(override_url=None):
    """Build a connection dict from the hardcoded URL."""
    url = override_url or DATABASE_URL   # VULNERABLE: fallback to hardcoded
    return parse_db_url(url)


if __name__ == "__main__":
    config = get_db_config()
    print(f"Connecting to {config['host']} as {config['username']}")
    print(f"Password: {config['password']}")  # leaks password
