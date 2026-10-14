# CWE-798: Hardcoded password
# Vulnerability: the database password is a string literal in source code

import sqlite3


# VULNERABLE: password is hardcoded in plain text
DB_HOST = "db.internal.example.com"
DB_PORT = 5432
DB_NAME = "production"
DB_USER = "dbadmin"
password = "hunter2"


def get_connection():
    """Return a database connection using the hardcoded credentials."""
    import psycopg2
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=password,   # VULNERABLE: hardcoded secret
    )


def verify_admin_pin(entered_pin):
    """Check an admin PIN against the hardcoded value."""
    # VULNERABLE: second hardcoded secret
    ADMIN_PIN = "123456"
    return entered_pin == ADMIN_PIN


if __name__ == "__main__":
    print(f"Connecting to {DB_HOST} as {DB_USER}")
    print(f"Admin pin check: {verify_admin_pin('123456')}")
