# CWE-89: SQL Injection via string concatenation
# Vulnerability: + operator builds query with raw user input

import sqlite3


def get_order(order_id):
    """Retrieve an order — vulnerable to injection via concatenation."""
    conn = sqlite3.connect("orders.db")
    cursor = conn.cursor()

    # VULNERABLE: direct string concatenation into SQL
    query = "SELECT * FROM orders WHERE id = " + str(order_id)
    cursor.execute(query)

    row = cursor.fetchone()
    conn.close()
    return row


def find_by_email(email):
    """Look up account by email — also uses concatenation."""
    conn = sqlite3.connect("orders.db")
    cursor = conn.cursor()

    sql = "SELECT id, name FROM accounts WHERE email = '" + email + "'"
    cursor.execute(sql)

    result = cursor.fetchone()
    conn.close()
    return result


if __name__ == "__main__":
    # Attacker passes: 1 OR 1=1
    print(get_order("1 OR 1=1"))
    # Email injection: ' OR ''='
    print(find_by_email("x' OR ''='"))
