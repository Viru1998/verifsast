# CWE-89: SQL Injection via Flask request.args
# Vulnerability: HTTP query parameter concatenated directly into SQL

import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)


def get_db():
    return sqlite3.connect("app.db")


@app.route("/search")
def search_users():
    # VULNERABLE: request.args value goes straight into the query string
    name = request.args.get("name", "")
    conn = get_db()
    cursor = conn.cursor()

    query = "SELECT id, username, role FROM users WHERE username = '" + name + "'"
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()

    return jsonify({"results": rows})


@app.route("/report")
def report():
    # VULNERABLE: second injection point via f-string
    start = request.args.get("start", "2024-01-01")
    end = request.args.get("end", "2024-12-31")

    conn = get_db()
    cursor = conn.cursor()
    sql = f"SELECT * FROM orders WHERE created_at BETWEEN '{start}' AND '{end}'"
    cursor.execute(sql)
    rows = cursor.fetchall()
    conn.close()
    return jsonify(rows)


if __name__ == "__main__":
    app.run(debug=True)
