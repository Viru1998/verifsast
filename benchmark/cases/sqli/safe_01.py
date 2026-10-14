# CWE-89: Safe — parameterised query with sqlite3 using ? placeholder
# No vulnerability: user input is passed as a separate parameter tuple,
# never interpolated into the SQL string.

import sqlite3


def get_user_by_name(username):
    """Fetch user record using a properly parameterised query."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    # SAFE: the ? placeholder is handled by the DB driver; username is never
    # concatenated into the query string.
    sql = "SELECT id, name, email FROM users WHERE name = ?"
    cursor.execute(sql, (username,))

    row = cursor.fetchone()
    conn.close()
    return row


def get_orders_for_user(user_id, status):
    """Retrieve orders with two parameterised conditions."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    sql = "SELECT * FROM orders WHERE user_id = ? AND status = ?"
    cursor.execute(sql, (user_id, status))

    rows = cursor.fetchall()
    conn.close()
    return rows


if __name__ == "__main__":
    # Even with a malicious-looking string, the DB driver treats it as data.
    print(get_user_by_name("admin' OR '1'='1"))
    print(get_orders_for_user(1, "pending"))
