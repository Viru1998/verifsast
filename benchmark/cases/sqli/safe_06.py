# CWE-89: Safe — sqlite3 named dict params with :name placeholders
# Using the dictionary form of sqlite3 parameterisation.

import sqlite3


def find_article(slug, published=True):
    """SAFE: named dict params prevent injection."""
    conn = sqlite3.connect("blog.db")
    cursor = conn.cursor()

    # SAFE: :slug and :published are named placeholders consumed by sqlite3
    sql = "SELECT title, body FROM articles WHERE slug = :slug AND published = :pub"
    cursor.execute(sql, {"slug": slug, "pub": int(published)})

    row = cursor.fetchone()
    conn.close()
    return row


def list_comments(post_id, status="approved"):
    """SAFE: two named params in one query."""
    conn = sqlite3.connect("blog.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT author, body, created_at FROM comments "
        "WHERE post_id = :post_id AND status = :status",
        {"post_id": post_id, "status": status},
    )
    rows = cursor.fetchall()
    conn.close()
    return rows


def insert_comment(post_id, author, body):
    """SAFE: INSERT with named params."""
    conn = sqlite3.connect("blog.db")
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO comments (post_id, author, body) VALUES (:post_id, :author, :body)",
        {"post_id": post_id, "author": author, "body": body},
    )
    conn.commit()
    conn.close()


if __name__ == "__main__":
    print(find_article("hello-world"))
