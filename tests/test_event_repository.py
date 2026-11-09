import pytest
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database.base import Base
from app.database.repositories.event_repository import EventRepository


@pytest.fixture
def db_session():
    """
    Create an isolated in-memory SQLite database
    for repository tests.

    The database is destroyed after the test finishes.
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


def test_create_event(db_session):
    """
    Verify that the repository creates a filesystem event.
    """

    repository = EventRepository(db_session)

    event = repository.create_event(
        event_type="modified",
        source_path="data/sandbox/test_document.txt",
        file_extension=".txt",
        is_directory=False
    )

    assert event.id is not None
    assert event.event_type == "MODIFIED"
    assert event.source_path == "data/sandbox/test_document.txt"
    assert event.file_extension == ".txt"
    assert event.is_directory is False
    assert event.timestamp is not None

def test_get_event_by_id(db_session):
    """
    Verify that an event can be retrieved using its ID.
    """

    repository = EventRepository(db_session)

    created_event = repository.create_event(
        event_type="CREATED",
        source_path="data/sandbox/retrieval_test.txt",
        file_extension=".txt"
    )

    retrieved_event = repository.get_event_by_id(
        created_event.id
    )

    assert retrieved_event is not None
    assert retrieved_event.id == created_event.id
    assert retrieved_event.event_type == "CREATED"
    assert retrieved_event.source_path == "data/sandbox/retrieval_test.txt"
    
def test_get_recent_events(db_session):
    """
    Verify that recent events are retrieved
    in descending timestamp order.
    """

    repository = EventRepository(db_session)

    first_event = repository.create_event(
        event_type="CREATED",
        source_path="data/sandbox/first.txt",
        timestamp=datetime(2026, 11, 1, 10, 0, tzinfo=timezone.utc)
    )

    second_event = repository.create_event(
        event_type="MODIFIED",
        source_path="data/sandbox/second.txt",
        timestamp=datetime(2026, 11, 2, 10, 0, tzinfo=timezone.utc)
    )

    third_event = repository.create_event(
        event_type="DELETED",
        source_path="data/sandbox/third.txt",
        timestamp=datetime(2026, 11, 3, 10, 0, tzinfo=timezone.utc)
    )

    events = repository.get_recent_events(limit=2)

    assert len(events) == 2
    assert events[0].id == third_event.id
    assert events[1].id == second_event.id
    
def test_get_events_by_type(db_session):
    """
    Verify that events can be filtered by event type.
    """

    repository = EventRepository(db_session)

    repository.create_event(
        event_type="CREATED",
        source_path="data/sandbox/file1.txt"
    )

    repository.create_event(
        event_type="MODIFIED",
        source_path="data/sandbox/file2.txt"
    )

    repository.create_event(
        event_type="MODIFIED",
        source_path="data/sandbox/file3.txt"
    )

    events = repository.get_events_by_type(
        event_type="modified",
        limit=10
    )

    assert len(events) == 2

    for event in events:
        assert event.event_type == "MODIFIED"
        
def test_get_events_by_path(db_session):
    """
    Verify that events can be retrieved using
    either their source path or destination path.
    """

    repository = EventRepository(db_session)

    repository.create_event(
        event_type="CREATED",
        source_path="data/sandbox/document.txt"
    )

    repository.create_event(
        event_type="MOVED",
        source_path="data/sandbox/old_name.txt",
        destination_path="data/sandbox/new_name.txt"
    )

    source_results = repository.get_events_by_path(
        "data/sandbox/old_name.txt"
    )

    destination_results = repository.get_events_by_path(
        "data/sandbox/new_name.txt"
    )

    assert len(source_results) == 1
    assert source_results[0].event_type == "MOVED"

    assert len(destination_results) == 1
    assert destination_results[0].event_type == "MOVED"
    
def test_create_event_rejects_empty_event_type(db_session):
    """
    Verify that an empty event type is rejected.
    """

    repository = EventRepository(db_session)

    with pytest.raises(ValueError):
        repository.create_event(
            event_type="",
            source_path="data/sandbox/test.txt"
        )


def test_create_event_rejects_empty_source_path(db_session):
    """
    Verify that an empty source path is rejected.
    """

    repository = EventRepository(db_session)

    with pytest.raises(ValueError):
        repository.create_event(
            event_type="CREATED",
            source_path=" "
        )


def test_get_recent_events_rejects_invalid_limit(db_session):
    """
    Verify that invalid result limits are rejected.
    """

    repository = EventRepository(db_session)

    with pytest.raises(ValueError):
        repository.get_recent_events(limit=0)
        
def test_create_event_rejects_naive_timestamp(db_session):
    """
    Verify that timestamps without timezone information
    are rejected.
    """

    repository = EventRepository(db_session)

    naive_timestamp = datetime(2026, 11, 4, 10, 0)

    with pytest.raises(ValueError):
        repository.create_event(
            event_type="CREATED",
            source_path="data/sandbox/test.txt",
            timestamp=naive_timestamp
        )


def test_create_event_normalizes_timestamp_to_utc(db_session):
    """
    Verify that timestamps are converted to UTC
    before being stored.
    """

    from datetime import timedelta

    repository = EventRepository(db_session)

    timestamp = datetime(
        2026, 11, 4, 15, 30,
        tzinfo=timezone(timedelta(hours=5, minutes=30))
    )

    event = repository.create_event(
        event_type="CREATED",
        source_path="data/sandbox/utc_test.txt",
        timestamp=timestamp
    )

    assert event.timestamp == datetime(
        2026, 11, 4, 10, 0,
        tzinfo=timezone.utc
    )
def test_create_event_with_entropy(db_session):
    """
    Verify that a valid entropy measurement is stored.
    """

    repository = EventRepository(db_session)

    event = repository.create_event(
        event_type="MODIFIED",
        source_path="data/sandbox/entropy_test.txt",
        entropy=7.5
    )

    assert event.entropy == 7.5


def test_create_event_without_entropy(db_session):
    """
    Verify that entropy can remain unavailable.
    """

    repository = EventRepository(db_session)

    event = repository.create_event(
        event_type="CREATED",
        source_path="data/sandbox/new_file.txt"
    )

    assert event.entropy is None


@pytest.mark.parametrize(
    "invalid_entropy",
    [
        -0.1,
        8.1,
        float("nan"),
        float("inf"),
        -float("inf"),
        True,
        "7.5"
    ]
)
def test_create_event_rejects_invalid_entropy(
    db_session,
    invalid_entropy
):
    """
    Verify that invalid entropy measurements are rejected.
    """

    repository = EventRepository(db_session)

    with pytest.raises(ValueError):
        repository.create_event(
            event_type="MODIFIED",
            source_path="data/sandbox/invalid_entropy.txt",
            entropy=invalid_entropy
        )