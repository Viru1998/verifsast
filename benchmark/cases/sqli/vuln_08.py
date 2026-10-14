# CWE-89: SQL Injection — multi-param login query with % format
# Vulnerability: both username and password inserted via Python % formatting

import sqlite3


def authenticate(username, password):
    """Authenticate a user — both parameters are injectable."""
    conn = sqlite3.connect("auth.db")
    cursor = conn.cursor()

    # VULNERABLE: multi-value % format with user-controlled inputs
    query = (
        "SELECT id, role FROM users "
        "WHERE username = '%s' AND password_hash = '%s'"
        % (username, password)
    )
    cursor.execute(query)
    row = cursor.fetchone()
    conn.close()

    if row:
        return {"user_id": row[0], "role": row[1], "authenticated": True}
    return {"authenticated": False}


def update_last_login(user_id, ip_address):
    """Record the last login IP — also vulnerable."""
    conn = sqlite3.connect("auth.db")
    cursor = conn.cursor()

    sql = (
        "UPDATE users SET last_login_ip = '%s', last_login_at = datetime('now') "
        "WHERE id = %s" % (ip_address, user_id)
    )
    cursor.execute(sql)
    conn.commit()
    conn.close()


if __name__ == "__main__":
    # Classic bypass: username = "admin'--"
    result = authenticate("admin'--", "anything")
    print(result)
