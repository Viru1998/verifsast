# CWE-89: SQL Injection — DELETE with concatenated table name / condition
# Vulnerability: table name and WHERE clause built from user input via concatenation

import sqlite3


def delete_record(table_name, record_id):
    """Delete a record from the given table — both args injectable."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    # VULNERABLE: table_name cannot be parameterised by the DB driver;
    # using concatenation here allows an attacker to alter the query.
    query = "DELETE FROM " + table_name + " WHERE id = " + str(record_id)
    cursor.execute(query)
    conn.commit()

    affected = cursor.rowcount
    conn.close()
    return affected


def purge_by_status(status, before_date):
    """Purge records older than a date and matching status."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    # VULNERABLE: f-string with two user-controlled values
    sql = f"DELETE FROM audit_log WHERE status = '{status}' AND created_at < '{before_date}'"
    cursor.execute(sql)
    conn.commit()
    count = cursor.rowcount
    conn.close()
    return count


if __name__ == "__main__":
    # Attacker: table_name = "users WHERE 1=1 --"
    n = delete_record("users WHERE 1=1 --", 0)
    print(f"Deleted {n} rows")
