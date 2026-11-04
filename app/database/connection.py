
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine


DATABASE_PATH = Path("data/rdrs.db")


def create_database_engine():
    """
    Create and configure the SQLite database engine.
    """

    DATABASE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    database_url = f"sqlite:///{DATABASE_PATH.resolve().as_posix()}"

    engine = create_engine(
        database_url,
        echo=False,
        connect_args={"check_same_thread": False}
    )

    @event.listens_for(engine, "connect")
    def enable_sqlite_foreign_keys(
        dbapi_connection,
        connection_record
    ):
        """
        Enable SQLite foreign-key enforcement
        for every new database connection.
        """

        cursor = dbapi_connection.cursor()

        cursor.execute("PRAGMA foreign_keys=ON")

        cursor.close()

    return engine


def initialize_database(engine):
    """
    Create all database tables defined in the ORM models.

    Importing models registers their table metadata
    with the shared SQLAlchemy Base.
    """

    # Register all ORM models before creating tables.
    from app.database import models  # noqa: F401

    from app.database.base import Base

    Base.metadata.create_all(bind=engine)
