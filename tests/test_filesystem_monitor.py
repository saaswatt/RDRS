from contextlib import contextmanager

import pytest

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from watchdog.events import (
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileMovedEvent,
)

from app.database.base import Base
from app.database.models import Event
from app.detectors import filesystem_monitor


@pytest.fixture
def db_session():
    """
    Create an isolated in-memory SQLite database
    for filesystem monitor tests.
    """

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )

    Base.metadata.create_all(bind=engine)

    TestingSessionLocal = sessionmaker(
        bind=engine,
        autoflush=False,
        expire_on_commit=False
    )

    session = TestingSessionLocal()

    try:
        yield session

    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


@pytest.fixture
def event_handler(db_session, monkeypatch):
    """
    Create an event handler that uses the isolated
    test database instead of the production database.
    """

    @contextmanager
    def test_db_session():
        try:
            yield db_session
            db_session.commit()

        except Exception:
            db_session.rollback()
            raise

    monkeypatch.setattr(
        filesystem_monitor,
        "get_db_session",
        test_db_session
    )

    return filesystem_monitor.RDRSEventHandler()


def get_saved_events(db_session):
    """Retrieve all saved filesystem events."""

    statement = select(Event).order_by(Event.id)

    return list(db_session.scalars(statement).all())


def test_file_created_event_is_persisted(
    event_handler,
    db_session,
    monkeypatch
):
    """Verify that file creation is recorded with entropy."""

    monkeypatch.setattr(
        filesystem_monitor,
        "calculate_file_entropy",
        lambda path: 6.5
    )

    event = FileCreatedEvent(
        "data/sandbox/created.txt"
    )

    event_handler.on_created(event)

    events = get_saved_events(db_session)

    assert len(events) == 1
    assert events[0].event_type == "CREATED"
    assert events[0].source_path == "data/sandbox/created.txt"
    assert events[0].file_extension == ".txt"
    assert events[0].entropy == 6.5
    assert events[0].is_directory is False


def test_file_modified_event_is_persisted(
    event_handler,
    db_session,
    monkeypatch
):
    """Verify that file modification is recorded with entropy."""

    monkeypatch.setattr(
        filesystem_monitor,
        "calculate_file_entropy",
        lambda path: 7.2
    )

    event = FileModifiedEvent(
        "data/sandbox/modified.txt"
    )

    event_handler.on_modified(event)

    events = get_saved_events(db_session)

    assert len(events) == 1
    assert events[0].event_type == "MODIFIED"
    assert events[0].source_path == "data/sandbox/modified.txt"
    assert events[0].entropy == 7.2


def test_file_deleted_event_is_persisted(
    event_handler,
    db_session,
    monkeypatch
):
    """Verify that deletion is recorded without entropy calculation."""

    def unexpected_entropy_call(path):
        pytest.fail("Entropy should not be calculated for deleted files.")

    monkeypatch.setattr(
        filesystem_monitor,
        "calculate_file_entropy",
        unexpected_entropy_call
    )

    event = FileDeletedEvent(
        "data/sandbox/deleted.txt"
    )

    event_handler.on_deleted(event)

    events = get_saved_events(db_session)

    assert len(events) == 1
    assert events[0].event_type == "DELETED"
    assert events[0].source_path == "data/sandbox/deleted.txt"
    assert events[0].entropy is None


def test_file_moved_event_is_persisted(
    event_handler,
    db_session,
    monkeypatch
):
    """Verify that both paths are recorded for moved files."""

    def unexpected_entropy_call(path):
        pytest.fail("Entropy should not be calculated for moved files.")

    monkeypatch.setattr(
        filesystem_monitor,
        "calculate_file_entropy",
        unexpected_entropy_call
    )

    event = FileMovedEvent(
        "data/sandbox/old_name.txt",
        "data/sandbox/new_name.txt"
    )

    event_handler.on_moved(event)

    events = get_saved_events(db_session)

    assert len(events) == 1
    assert events[0].event_type == "MOVED"
    assert events[0].source_path == "data/sandbox/old_name.txt"
    assert events[0].destination_path == "data/sandbox/new_name.txt"
    assert events[0].entropy is None


@pytest.mark.parametrize(
    "event_class",
    [
        FileCreatedEvent,
        FileModifiedEvent,
        FileDeletedEvent,
        FileMovedEvent
    ]
)
def test_directory_events_are_ignored(
    event_handler,
    db_session,
    event_class
):
    """Verify that directory events are not persisted."""

    if event_class is FileMovedEvent:
        event = event_class(
            "data/sandbox/old_directory",
            "data/sandbox/new_directory"
        )
    else:
        event = event_class(
            "data/sandbox/test_directory"
        )

    event.is_directory = True

    if event_class is FileCreatedEvent:
        event_handler.on_created(event)

    elif event_class is FileModifiedEvent:
        event_handler.on_modified(event)

    elif event_class is FileDeletedEvent:
        event_handler.on_deleted(event)

    else:
        event_handler.on_moved(event)

    assert get_saved_events(db_session) == []


def test_event_is_persisted_when_entropy_calculation_fails(
    event_handler,
    db_session,
    monkeypatch
):
    """Verify that entropy failures do not prevent event persistence."""

    def failing_entropy_calculation(path):
        raise PermissionError("Access denied.")

    monkeypatch.setattr(
        filesystem_monitor,
        "calculate_file_entropy",
        failing_entropy_calculation
    )

    event = FileModifiedEvent(
        "data/sandbox/restricted.txt"
    )

    event_handler.on_modified(event)

    events = get_saved_events(db_session)

    assert len(events) == 1
    assert events[0].event_type == "MODIFIED"
    assert events[0].entropy is None


def test_event_is_persisted_after_unexpected_entropy_error(
    event_handler,
    db_session,
    monkeypatch
):
    """Verify that unexpected entropy errors are isolated."""

    def failing_entropy_calculation(path):
        raise RuntimeError("Unexpected entropy failure.")

    monkeypatch.setattr(
        filesystem_monitor,
        "calculate_file_entropy",
        failing_entropy_calculation
    )

    event = FileCreatedEvent(
        "data/sandbox/unexpected.txt"
    )

    event_handler.on_created(event)

    events = get_saved_events(db_session)

    assert len(events) == 1
    assert events[0].entropy is None


def test_database_failure_does_not_crash_event_handler(
    event_handler,
    monkeypatch
):
    """Verify that database failures are isolated from Watchdog."""

    @contextmanager
    def failing_db_session():
        raise RuntimeError("Simulated database failure.")
        yield

    monkeypatch.setattr(
        filesystem_monitor,
        "get_db_session",
        failing_db_session
    )

    event = FileDeletedEvent(
        "data/sandbox/database_failure.txt"
    )

    # The callback must handle the exception internally.
    event_handler.on_deleted(event)