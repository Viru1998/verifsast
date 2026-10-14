# CWE-89: SQL Injection via Python % operator with psycopg2
# Vulnerability: uses Python's % string operator, NOT psycopg2 parameterisation.
# This looks like the safe pattern but the % is applied to the string BEFORE
# the query reaches the DB driver, so injection is still possible.

import psycopg2


def get_connection():
    return psycopg2.connect("dbname=appdb user=appuser password=secret host=localhost")


def find_user(username, password):
    """Login lookup — dangerous use of Python % with psycopg2."""
    conn = get_connection()
    cur = conn.cursor()

    # VULNERABLE: Python's % operator formats the string before psycopg2 sees it.
    # This is NOT the same as the safe: cur.execute(sql, (username, password))
    sql = "SELECT id FROM users WHERE username = '%s' AND password = '%s'" % (
        username,
        password,
    )
    cur.execute(sql)  # psycopg2 receives a pre-formatted, injectable string

    row = cur.fetchone()
    cur.close()
    conn.close()
    return row


def get_profile(user_id):
    conn = get_connection()
    cur = conn.cursor()
    # VULNERABLE: same pattern with an integer field
    cur.execute("SELECT * FROM profiles WHERE user_id = %d" % user_id)
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row


if __name__ == "__main__":
    print(find_user("admin", "' OR '1'='1"))
