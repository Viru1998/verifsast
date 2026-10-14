# CWE-89: Safe — hardcoded query, no user input at all
# There is nothing to inject because the entire SQL string is a literal
# with no dynamic components.

import sqlite3


def count_active_users():
    """Return the number of active users — fully hardcoded query."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    # SAFE: literal SQL string, zero user-controlled data.
    cursor.execute("SELECT COUNT(*) FROM users WHERE active = 1")
    (count,) = cursor.fetchone()
    conn.close()
    return count


def get_schema_version():
    """Read the current DB schema version — also hardcoded."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    cursor.execute("SELECT version FROM schema_migrations ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None


def list_admin_emails():
    """List all admin email addresses — static query."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT email FROM users WHERE role = 'admin'")
    rows = cursor.fetchall()
    conn.close()
    return [r[0] for r in rows]


if __name__ == "__main__":
    print("Active users:", count_active_users())
    print("Schema version:", get_schema_version())
