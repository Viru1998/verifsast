# CWE-89: Safe — psycopg2 with %s placeholder (TRUE parameterisation)
# Near-miss: the %s looks like Python string formatting, but here it is
# psycopg2's own placeholder syntax — user input is passed in the args tuple
# and is NEVER formatted into the string by Python.

import psycopg2


def get_connection():
    return psycopg2.connect("dbname=appdb user=appuser password=secret host=localhost")


def find_user(username, password):
    """Login lookup using psycopg2 parameterised query."""
    conn = get_connection()
    cur = conn.cursor()

    # SAFE: the %s here are psycopg2 placeholders, not Python % formatting.
    # The tuple is the second argument to execute(), handled entirely by the driver.
    sql = "SELECT id, role FROM users WHERE username = %s AND password_hash = %s"
    cur.execute(sql, (username, password))

    row = cur.fetchone()
    cur.close()
    conn.close()
    return row


def get_profile(user_id):
    """Profile lookup — integer parameter, still parameterised."""
    conn = get_connection()
    cur = conn.cursor()

    # SAFE: even for integers, passing via the args tuple is correct.
    cur.execute("SELECT * FROM profiles WHERE user_id = %s", (user_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row


if __name__ == "__main__":
    print(find_user("alice", "correcthorsebatterystaple"))
