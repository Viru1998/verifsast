# CWE-89: SQL Injection — UPDATE statement with f-string
# Vulnerability: UPDATE query built with f-string from user-supplied values

import sqlite3


def update_user_email(user_id, new_email):
    """Update a user's email address — vulnerable UPDATE with f-string."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # VULNERABLE: f-string in an UPDATE statement
    sql = f"UPDATE users SET email = '{new_email}' WHERE id = {user_id}"
    cursor.execute(sql)
    conn.commit()
    conn.close()


def update_profile(user_id, bio, location):
    """Update profile fields — multiple injectable columns."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # VULNERABLE: both bio and location are user-controlled strings
    query = (
        f"UPDATE profiles SET bio = '{bio}', location = '{location}' "
        f"WHERE user_id = {user_id}"
    )
    cursor.execute(query)
    conn.commit()
    conn.close()


def set_display_name(username, display_name):
    """Set display name — another UPDATE injection point."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(
        f"UPDATE users SET display_name = '{display_name}' WHERE username = '{username}'"
    )
    conn.commit()
    conn.close()


if __name__ == "__main__":
    # Attacker payload: email = "x', admin=1 WHERE id=1 --"
    update_user_email(42, "x', is_admin=1 WHERE id=1 --")
