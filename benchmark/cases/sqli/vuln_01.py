# CWE-89: SQL Injection via % string formatting
# Vulnerability: user input is formatted directly into the SQL query string

import sqlite3


def get_user_by_name(username):
    """Fetch a user record by username — vulnerable to SQL injection."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    # VULNERABLE: user-controlled 'username' is interpolated with % formatting
    query = "SELECT id, name, email FROM users WHERE name = '%s'" % username
    cursor.execute(query)

    row = cursor.fetchone()
    conn.close()
    return row


if __name__ == "__main__":
    # Attacker input: ' OR '1'='1
    result = get_user_by_name("admin' OR '1'='1")
    print(result)
