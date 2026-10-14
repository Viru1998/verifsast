# CWE-89: Safe — user input cast to int() before use in query with ?
# Near-miss: the query looks like it could be injectable, but the hard int()
# cast ensures only a valid integer can reach the placeholder.

import sqlite3


def get_order(order_id_str):
    """
    Fetch an order by ID.
    order_id_str comes from user input (e.g. a URL parameter) but is cast
    to int before it is placed in the parameterised query.
    If the cast fails, a ValueError is raised — never a DB error.
    """
    order_id = int(order_id_str)  # raises ValueError if not a valid integer

    conn = sqlite3.connect("orders.db")
    cursor = conn.cursor()

    # SAFE: only a genuine integer can reach here; parameterised with ?
    cursor.execute("SELECT * FROM orders WHERE id = ?", (order_id,))
    row = cursor.fetchone()
    conn.close()
    return row


def get_page(page_str, page_size=20):
    """Paginated query — both values are integers derived from user input."""
    page = max(1, int(page_str))
    offset = (page - 1) * page_size

    conn = sqlite3.connect("orders.db")
    cursor = conn.cursor()

    # SAFE: offset and page_size are genuine ints, passed as params
    cursor.execute(
        "SELECT * FROM orders ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (page_size, offset),
    )
    rows = cursor.fetchall()
    conn.close()
    return rows


if __name__ == "__main__":
    try:
        print(get_order("42"))
        print(get_order("abc"))  # raises ValueError, never reaches DB
    except ValueError as exc:
        print(f"Invalid input: {exc}")
