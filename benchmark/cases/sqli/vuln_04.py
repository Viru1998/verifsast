# CWE-89: SQL Injection via .format()
# Vulnerability: str.format() interpolates user data into the query

import sqlite3


def get_article(slug):
    """Fetch article by URL slug — vulnerable via .format()."""
    conn = sqlite3.connect("blog.db")
    cursor = conn.cursor()

    # VULNERABLE: .format() embeds user-controlled slug into SQL
    query = "SELECT title, body, author FROM articles WHERE slug = '{slug}'".format(
        slug=slug
    )
    cursor.execute(query)

    row = cursor.fetchone()
    conn.close()
    return row


def list_comments(post_id, status):
    """List comments filtered by status — doubly vulnerable."""
    conn = sqlite3.connect("blog.db")
    cursor = conn.cursor()

    sql = "SELECT * FROM comments WHERE post_id = {pid} AND status = '{st}'".format(
        pid=post_id, st=status
    )
    cursor.execute(sql)
    rows = cursor.fetchall()
    conn.close()
    return rows


if __name__ == "__main__":
    # Attacker: slug = "foo' OR '1'='1' --"
    print(get_article("foo' OR '1'='1' --"))
