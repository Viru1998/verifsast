# CWE-89: Safe — function builds a display string that looks SQL-like
# but never connects to a database.  Near-miss for false positive testing.

def build_query_display(table, filters):
    """
    Build a human-readable string representation of a query for logging/display.
    This string is NEVER executed against a database — it is only printed.
    """
    where_parts = []
    for col, val in filters.items():
        # Escaping for display purposes only
        safe_val = str(val).replace("'", "''")
        where_parts.append(f"{col} = '{safe_val}'")

    where_clause = " AND ".join(where_parts) if where_parts else "1=1"
    display = f"SELECT * FROM {table} WHERE {where_clause}"
    return display


def explain_filter(column, operator, value):
    """Describe what a filter does in pseudo-SQL — display only."""
    display_value = repr(value)
    return f"Filter: {column} {operator} {display_value}"


def summarise_operation(op_type, table, record_count):
    """Build an audit log message that looks SQL-like but is just a string."""
    return f"{op_type.upper()} {record_count} rows from {table}"


if __name__ == "__main__":
    display = build_query_display(
        "users",
        {"username": "alice", "role": "admin"},
    )
    print("Display string (never executed):", display)

    print(explain_filter("age", ">=", 18))
    print(summarise_operation("select", "orders", 42))
