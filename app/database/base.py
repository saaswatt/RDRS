from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """
    Base class for all RDRS database models.

    All ORM models inherit from this class.
    SQLAlchemy uses this base to maintain
    metadata about the database tables.
    """

    pass