
from contextlib import contextmanager
from typing import Generator

from sqlalchemy.orm import Session, sessionmaker

from app.database.connection import create_database_engine
from app.core.logging import get_logger


system_logger = get_logger("system")
error_logger = get_logger("errors")

# Create one database engine for this application process.
engine = create_database_engine()

# Configure the session factory.
SessionLocal = sessionmaker(
    bind=engine,
    class_=Session,
    autoflush=False,
    expire_on_commit=False
)


@contextmanager
def get_db_session() -> Generator[Session, None, None]:
    """
    Provide a managed database session.

    Successful transactions are committed.
    Failed transactions are rolled back.
    Sessions are always closed.
    """

    session = SessionLocal()

    try:
        yield session

        session.commit()

        system_logger.debug(
            "Database transaction committed successfully."
        )

    except Exception as exc:
        session.rollback()

        error_logger.exception(
            f"Database transaction failed: {exc}"
        )

        raise

    finally:
        session.close()
