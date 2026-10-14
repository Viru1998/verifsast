# CWE-89: Safe — SQLAlchemy text() with :param bindparams
# text() with explicit bindparams is safe; the driver handles escaping.

from sqlalchemy import create_engine, text

engine = create_engine("sqlite:///app.db", echo=False)


def get_user(username):
    """SAFE: SQLAlchemy text() with named bindparam :username."""
    with engine.connect() as conn:
        result = conn.execute(
            text("SELECT id, email, role FROM users WHERE username = :username"),
            {"username": username},
        )
        return result.fetchone()


def search_orders(user_id, status, limit=20):
    """SAFE: multiple named bindparams — no string interpolation."""
    with engine.connect() as conn:
        result = conn.execute(
            text(
                "SELECT id, total, created_at FROM orders "
                "WHERE user_id = :uid AND status = :status "
                "ORDER BY created_at DESC LIMIT :lim"
            ),
            {"uid": user_id, "status": status, "lim": limit},
        )
        return result.fetchall()


def update_email(user_id, new_email):
    """SAFE: UPDATE using bindparams."""
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE users SET email = :email WHERE id = :uid"),
            {"email": new_email, "uid": user_id},
        )


if __name__ == "__main__":
    user = get_user("alice")
    print(user)
