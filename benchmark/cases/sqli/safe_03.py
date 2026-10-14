# CWE-89: Safe — SQLAlchemy ORM .filter() (no raw SQL)
# The ORM builds parameterised queries internally; user input never touches
# a raw SQL string.

from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, Session

Base = declarative_base()
engine = create_engine("sqlite:///app.db", echo=False)


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String)
    email = Column(String)
    role = Column(String)


class Order(Base):
    __tablename__ = "orders"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer)
    status = Column(String)


def find_user_by_name(username):
    """SAFE: ORM .filter() generates a parameterised query."""
    with Session(engine) as session:
        user = session.query(User).filter(User.username == username).first()
        return user


def list_orders(user_id, status):
    """SAFE: chained filters — still parameterised by SQLAlchemy."""
    with Session(engine) as session:
        orders = (
            session.query(Order)
            .filter(Order.user_id == user_id, Order.status == status)
            .all()
        )
        return orders


if __name__ == "__main__":
    Base.metadata.create_all(engine)
    user = find_user_by_name("alice")
    print(user)
