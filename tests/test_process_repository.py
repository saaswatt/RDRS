
from datetime import datetime, timezone

import pytest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.database.models import Process
from app.database.base import Base
from app.database.repositories.process_repository import ProcessRepository
from copy import deepcopy
from app.database.repositories.process_repository import ProcessRepository

@pytest.fixture
def db_session():
    """
    Create an isolated in-memory SQLite database
    for process repository tests.
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


def test_create_process_snapshot(db_session):
    """
    Verify that a process snapshot can be created
    and staged for database insertion.
    """

    repository = ProcessRepository(db_session)

    process_info = {
        "pid": 12345,
        "name": "test.exe",
        "executable_path": "C:\\Test\\test.exe",
        "parent_pid": 100,
        "process_create_time": 1793800000.0,
        "cpu_percent": 2.5,
        "memory_percent": 1.5,
        "memory_rss": 1024000,
        "disk_read_bytes": 2048,
        "disk_write_bytes": 4096,
        "username": "TEST_USER",
        "status": "running",
        "timestamp": datetime.now(timezone.utc)
    }

    process = repository.create_process_snapshot(process_info)

    assert process.id is not None
    assert process.pid == 12345
    assert process.name == "test.exe"
    assert process.executable_path == "C:\\Test\\test.exe"
    assert process.parent_pid == 100
    assert process.cpu_percent == 2.5
    assert process.memory_percent == 1.5
    assert process.memory_rss == 1024000
    assert process.disk_read_bytes == 2048
    assert process.disk_write_bytes == 4096
    assert process.username == "TEST_USER"
    assert process.status == "running"
    assert process.timestamp is not None

def test_retrieve_process_snapshot(db_session):
    """
    Verify that a committed process snapshot
    can be retrieved from the database.
    """

    repository = ProcessRepository(db_session)

    process_info = {
        "pid": 54321,
        "name": "retrieval_test.exe",
        "executable_path": "C:\\Test\\retrieval_test.exe",
        "parent_pid": 200,
        "process_create_time": 1793800000.0,
        "cpu_percent": 4.5,
        "memory_percent": 2.0,
        "memory_rss": 2048000,
        "disk_read_bytes": 4096,
        "disk_write_bytes": 8192,
        "username": "TEST_USER",
        "status": "running",
        "timestamp": datetime.now(timezone.utc)
    }

    created_process = repository.create_process_snapshot(process_info)

    # The repository stages the record.
    # The caller controls the transaction.
    db_session.commit()

    # Retrieve the committed record.
    retrieved_process = db_session.get(
        Process,
        created_process.id
    )

    assert retrieved_process is not None
    assert retrieved_process.pid == 54321
    assert retrieved_process.name == "retrieval_test.exe"
    assert retrieved_process.cpu_percent == 4.5
    assert retrieved_process.memory_rss == 2048000
    assert retrieved_process.status == "running"

def test_process_snapshot_rollback(db_session):
    """
    Verify that a failed transaction rolls back
    the process snapshot.
    """

    repository = ProcessRepository(db_session)

    process_info = {
        "pid": 67890,
        "name": "rollback_test.exe",
        "executable_path": "C:\\Test\\rollback_test.exe",
        "parent_pid": 300,
        "process_create_time": 1793800000.0,
        "cpu_percent": 1.0,
        "memory_percent": 0.5,
        "memory_rss": 512000,
        "disk_read_bytes": 1024,
        "disk_write_bytes": 2048,
        "username": "TEST_USER",
        "status": "running",
        "timestamp": datetime.now(timezone.utc)
    }

    created_process = repository.create_process_snapshot(process_info)

    process_id = created_process.id

    # Simulate a failed transaction.
    db_session.rollback()

    # Verify that the snapshot was not persisted.
    retrieved_process = db_session.get(Process, process_id)

    assert retrieved_process is None
def test_process_snapshot_rollback(db_session):
    """
    Verify that a failed transaction rolls back
    the process snapshot.
    """

    repository = ProcessRepository(db_session)

    process_info = {
        "pid": 67890,
        "name": "rollback_test.exe",
        "executable_path": "C:\\Test\\rollback_test.exe",
        "parent_pid": 300,
        "process_create_time": 1793800000.0,
        "cpu_percent": 1.0,
        "memory_percent": 0.5,
        "memory_rss": 512000,
        "disk_read_bytes": 1024,
        "disk_write_bytes": 2048,
        "username": "TEST_USER",
        "status": "running",
        "timestamp": datetime.now(timezone.utc)
    }

    created_process = repository.create_process_snapshot(process_info)

    process_id = created_process.id

    db_session.rollback()

    retrieved_process = db_session.get(Process, process_id)

    assert retrieved_process is None

def test_create_process_snapshot_rejects_invalid_pid(db_session):
    """
    Verify that invalid PIDs are rejected.
    """

    repository = ProcessRepository(db_session)

    process_info = {
        "pid": 0,
        "name": "invalid.exe",
        "timestamp": datetime.now(timezone.utc)
    }

    with pytest.raises(ValueError):
        repository.create_process_snapshot(process_info)
def test_create_process_snapshot_rejects_negative_cpu(db_session):
    """
    Verify that negative CPU percentages are rejected.
    """

    repository = ProcessRepository(db_session)

    process_info = {
        "pid": 12345,
        "name": "invalid_cpu.exe",
        "cpu_percent": -1.0,
        "timestamp": datetime.now(timezone.utc)
    }

    with pytest.raises(ValueError):
        repository.create_process_snapshot(process_info)
        

@pytest.mark.parametrize(
    "field,value",
    [
        ("memory_percent", -1.0),
        ("memory_percent", 100.1),
        ("memory_percent", float("nan")),
        ("memory_percent", float("inf")),
        ("memory_percent", True),
    ],
)
def test_rejects_invalid_memory_percent(db_session, field, value):
    repository = ProcessRepository(db_session)

    process_info = {
        "pid": 12345,
        "name": "invalid_memory.exe",
        "timestamp": datetime.now(timezone.utc),
        field: value,
    }

    with pytest.raises(ValueError):
        repository.create_process_snapshot(process_info)


@pytest.mark.parametrize(
    "field,value",
    [
        ("memory_rss", -1),
        ("memory_rss", True),
        ("disk_read_bytes", -1),
        ("disk_read_bytes", True),
        ("disk_write_bytes", -1),
        ("disk_write_bytes", True),
        ("parent_pid", -1),
        ("parent_pid", True),
    ],
)
def test_rejects_invalid_integer_fields(db_session, field, value):
    repository = ProcessRepository(db_session)

    process_info = {
        "pid": 12345,
        "name": "invalid_integer.exe",
        "timestamp": datetime.now(timezone.utc),
        field: value,
    }

    with pytest.raises(ValueError):
        repository.create_process_snapshot(process_info)


@pytest.mark.parametrize(
    "value",
    [
        -1.0,
        float("nan"),
        float("inf"),
        True,
    ],
)
def test_rejects_invalid_process_create_time(db_session, value):
    repository = ProcessRepository(db_session)

    process_info = {
        "pid": 12345,
        "name": "invalid_creation_time.exe",
        "timestamp": datetime.now(timezone.utc),
        "process_create_time": value,
    }

    with pytest.raises(ValueError):
        repository.create_process_snapshot(process_info)


@pytest.mark.parametrize(
    "field",
    [
        "executable_path",
        "username",
        "status",
    ],
)
def test_rejects_invalid_optional_string_fields(db_session, field):
    repository = ProcessRepository(db_session)

    process_info = {
        "pid": 12345,
        "name": "invalid_string.exe",
        "timestamp": datetime.now(timezone.utc),
        field: 12345,
    }

    with pytest.raises(ValueError):
        repository.create_process_snapshot(process_info)


def test_accepts_unavailable_process_metrics(db_session):
    """
    Verify that unavailable measurements are stored as None,
    rather than being replaced with zero.
    """

    repository = ProcessRepository(db_session)

    process_info = {
        "pid": 12345,
        "name": "unavailable_metrics.exe",
        "timestamp": datetime.now(timezone.utc),
        "cpu_percent": None,
        "memory_percent": None,
        "memory_rss": None,
        "disk_read_bytes": None,
        "disk_write_bytes": None,
        "process_create_time": None,
        "parent_pid": None,
        "executable_path": None,
        "username": None,
        "status": None,
    }

    process = repository.create_process_snapshot(process_info)

    assert process.cpu_percent is None
    assert process.memory_percent is None
    assert process.memory_rss is None
    assert process.disk_read_bytes is None
    assert process.disk_write_bytes is None
    assert process.process_create_time is None
    assert process.parent_pid is None

def test_get_recent_snapshots(db_session):
    repository = ProcessRepository(db_session)

    first = repository.create_process_snapshot({
        "pid": 1001,
        "name": "first.exe",
        "timestamp": datetime(2026, 11, 1, 10, 0, tzinfo=timezone.utc)
    })

    second = repository.create_process_snapshot({
        "pid": 1002,
        "name": "second.exe",
        "timestamp": datetime(2026, 11, 1, 10, 1, tzinfo=timezone.utc)
    })

    db_session.commit()

    results = repository.get_recent_snapshots()

    assert len(results) == 2
    assert results[0].id == second.id
    assert results[1].id == first.id


def test_get_snapshots_by_pid(db_session):
    repository = ProcessRepository(db_session)

    first = repository.create_process_snapshot({
        "pid": 4500,
        "name": "app.exe",
        "timestamp": datetime(2026, 11, 1, 10, 0, tzinfo=timezone.utc)
    })

    second = repository.create_process_snapshot({
        "pid": 4500,
        "name": "app.exe",
        "timestamp": datetime(2026, 11, 1, 10, 1, tzinfo=timezone.utc)
    })

    repository.create_process_snapshot({
        "pid": 4501,
        "name": "other.exe",
        "timestamp": datetime(2026, 11, 1, 10, 2, tzinfo=timezone.utc)
    })

    db_session.commit()

    results = repository.get_snapshots_by_pid(4500)

    assert len(results) == 2
    assert results[0].id == second.id
    assert results[1].id == first.id


def test_get_snapshots_by_process_instance(db_session):
    repository = ProcessRepository(db_session)

    first_instance = repository.create_process_snapshot({
        "pid": 4500,
        "name": "app.exe",
        "process_create_time": 1793800000.0,
        "timestamp": datetime(2026, 11, 1, 10, 0, tzinfo=timezone.utc)
    })

    repository.create_process_snapshot({
        "pid": 4500,
        "name": "other.exe",
        "process_create_time": 1793800300.0,
        "timestamp": datetime(2026, 11, 1, 10, 5, tzinfo=timezone.utc)
    })

    repository.create_process_snapshot({
        "pid": 4500,
        "name": "app.exe",
        "process_create_time": 1793800000.0,
        "timestamp": datetime(2026, 11, 1, 10, 1, tzinfo=timezone.utc)
    })

    db_session.commit()

    results = repository.get_snapshots_by_process_instance(
        pid=4500,
        process_create_time=1793800000.0
    )

    assert len(results) == 2
    assert all(
        result.process_create_time == 1793800000.0
        for result in results
    )
    assert results[0].id != first_instance.id


@pytest.mark.parametrize("limit", [0, -1, True, 1.5, "10"])
def test_rejects_invalid_snapshot_limit(db_session, limit):
    repository = ProcessRepository(db_session)

    with pytest.raises(ValueError):
        repository.get_recent_snapshots(limit=limit)


def test_rejects_missing_process_creation_time(db_session):
    repository = ProcessRepository(db_session)

    with pytest.raises(ValueError):
        repository.get_snapshots_by_process_instance(
            pid=4500,
            process_create_time=None
        )
