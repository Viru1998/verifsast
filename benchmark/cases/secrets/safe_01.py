# CWE-798: Safe — password loaded from environment variable
# No secret is embedded in source; os.environ raises KeyError if unset,
# which fails loudly rather than silently using a bad default.

import os


def get_db_password():
    """Return the database password from the environment."""
    # SAFE: password comes from the environment, not from source code
    return os.environ["DB_PASSWORD"]


def get_db_config():
    """Build a database configuration dict from environment variables."""
    return {
        "host":     os.environ["DB_HOST"],
        "port":     int(os.environ.get("DB_PORT", "5432")),
        "database": os.environ["DB_NAME"],
        "user":     os.environ["DB_USER"],
        "password": os.environ["DB_PASSWORD"],  # SAFE: from env
    }


def connect():
    """Connect to the database using environment-sourced credentials."""
    config = get_db_config()
    # In a real app: return psycopg2.connect(**config)
    print(f"Connecting to {config['host']} as {config['user']}")
    return config


if __name__ == "__main__":
    try:
        cfg = get_db_config()
        print(f"DB host: {cfg['host']}, user: {cfg['user']}")
    except KeyError as exc:
        print(f"Missing required environment variable: {exc}")
