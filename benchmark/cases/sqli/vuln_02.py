# CWE-89: SQL Injection via f-string
# Vulnerability: f-string embeds user input directly into SQL

import sqlite3


def search_products(category):
    """Search products by category — vulnerable via f-string injection."""
    conn = sqlite3.connect("shop.db")
    cursor = conn.cursor()

    # VULNERABLE: f-string allows arbitrary SQL injection
    query = f"SELECT * FROM products WHERE category = '{category}' ORDER BY price"
    cursor.execute(query)

    results = cursor.fetchall()
    conn.close()
    return results


def delete_expired(cutoff_date):
    """Remove expired sessions — also vulnerable."""
    conn = sqlite3.connect("shop.db")
    cursor = conn.cursor()

    sql = f"DELETE FROM sessions WHERE expires_at < '{cutoff_date}'"
    cursor.execute(sql)
    conn.commit()
    conn.close()


if __name__ == "__main__":
    # Attacker payload: ' UNION SELECT username, password, NULL FROM users --
    items = search_products("toys' UNION SELECT username, password, NULL FROM users --")
    print(items)
