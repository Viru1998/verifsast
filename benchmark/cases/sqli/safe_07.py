# CWE-89: Safe — column name from a whitelist, then parameterised value
# Near-miss: the column name IS put into an f-string, but only after being
# validated against a strict whitelist — no user-supplied string reaches
# the column name unless it exactly matches an allowed identifier.

import sqlite3

ALLOWED_SORT_COLUMNS = {"id", "username", "email", "created_at", "role"}


def list_users_sorted(sort_column, search_term):
    """
    Sort users by a column chosen from a whitelist.
    The column name is injected via f-string ONLY after whitelist validation.
    The search_term is passed as a proper parameter.
    """
    if sort_column not in ALLOWED_SORT_COLUMNS:
        raise ValueError(f"Invalid sort column: {sort_column!r}")

    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    # SAFE: sort_column is validated; search_term uses ? placeholder
    sql = f"SELECT id, username, email FROM users WHERE username LIKE ? ORDER BY {sort_column}"
    cursor.execute(sql, (f"%{search_term}%",))

    rows = cursor.fetchall()
    conn.close()
    return rows


def get_user_field(user_id, field):
    """Return a single field from a user row — field whitelisted."""
    allowed_fields = {"id", "username", "email", "role", "created_at"}
    if field not in allowed_fields:
        raise ValueError(f"Field {field!r} not allowed")

    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT {field} FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None


if __name__ == "__main__":
    print(list_users_sorted("username", "alice"))
