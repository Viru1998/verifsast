# CWE-89: SQL Injection via dynamic ORDER BY with concatenation
# Vulnerability: ORDER BY clause built from unsanitised user input

import sqlite3


def list_users_sorted(sort_column, sort_dir="ASC"):
    """Return users sorted by a column the caller chooses — vulnerable."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    # VULNERABLE: sort_column and sort_dir go directly into the query;
    # ORDER BY cannot use parameterised placeholders in most DB drivers,
    # but the correct fix is a whitelist — not raw concatenation.
    query = (
        "SELECT id, username, email FROM users ORDER BY "
        + sort_column
        + " "
        + sort_dir
    )
    cursor.execute(query)

    rows = cursor.fetchall()
    conn.close()
    return rows


def paginated_products(offset, limit, order_by):
    """Products with pagination — order_by also injected."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    sql = (
        "SELECT * FROM products ORDER BY "
        + order_by
        + " LIMIT "
        + str(limit)
        + " OFFSET "
        + str(offset)
    )
    cursor.execute(sql)
    rows = cursor.fetchall()
    conn.close()
    return rows


if __name__ == "__main__":
    # Attacker payload: "1; DROP TABLE users --"
    print(list_users_sorted("1; DROP TABLE users --"))
