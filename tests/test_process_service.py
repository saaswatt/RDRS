
from contextlib import contextmanager

import pytest
from sqlalchemy import create_engine, select, func
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database.base import Base
from app.database.models import Process
from app.services import process_service


@pytest.fixture
def db_session():
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
def isolated_database(db_session, monkeypatch):
    @contextmanager
    def test_session():
        try:
            yield db_session
            db_session.commit()
        except Exception:
            db_session.rollback()
            raise

    monkeypatch.setattr(
        process_service,
        "get_db_session",
        test_session
    )

    return db_session

def make_process_snapshot(pid=1234, name="test-process.exe"):
    from datetime import datetime, timezone

    return {
        "pid": pid,
        "name": name,
        "executable_path": None,
        "parent_pid": 100,
        "process_create_time": 1700000000.0,
        "cpu_percent": 2.5,
        "memory_percent": 1.2,
        "memory_rss": 102400,
        "disk_read_bytes": 2048,
        "disk_write_bytes": 4096,
        "username": "test-user",
        "status": "running",
        "timestamp": datetime.now(timezone.utc)
    }


def test_collect_and_store_processes(isolated_database, monkeypatch):
    snapshots = [
        make_process_snapshot(1001, "process-one.exe"),
        make_process_snapshot(1002, "process-two.exe"),
        make_process_snapshot(1003, "process-three.exe")
    ]

    monkeypatch.setattr(
        process_service,
        "collect_running_processes",
        lambda: snapshots
    )

    result = process_service.collect_and_store_processes()

    assert result == {
        "collected": 3,
        "stored": 3,
        "skipped": 0
    }

    stored_count = isolated_database.scalar(
        select(func.count()).select_from(Process)
    )

    assert stored_count == 3


def test_invalid_snapshot_is_skipped(isolated_database, monkeypatch):
    snapshots = [
        make_process_snapshot(2001),
        {
            **make_process_snapshot(2002),
            "pid": -1
        },
        make_process_snapshot(2003)
    ]

    monkeypatch.setattr(
        process_service,
        "collect_running_processes",
        lambda: snapshots
    )

    result = process_service.collect_and_store_processes()

    assert result == {
        "collected": 3,
        "stored": 2,
        "skipped": 1
    }

    stored_count = isolated_database.scalar(
        select(func.count()).select_from(Process)
    )

    assert stored_count == 2


def test_database_failure_rolls_back_batch(isolated_database, monkeypatch):
    snapshots = [
        make_process_snapshot(3001),
        make_process_snapshot(3002)
    ]

    monkeypatch.setattr(
        process_service,
        "collect_running_processes",
        lambda: snapshots
    )

    def fail_on_second_snapshot(self, process_info):
        if process_info["pid"] == 3002:
            raise RuntimeError("Simulated database failure")

        process = Process(**process_info)
        self.session.add(process)
        self.session.flush()
        return process

    monkeypatch.setattr(
        process_service.ProcessRepository,
        "create_process_snapshot",
        fail_on_second_snapshot
    )

    with pytest.raises(RuntimeError, match="Simulated database failure"):
        process_service.collect_and_store_processes()

    stored_count = isolated_database.scalar(
        select(func.count()).select_from(Process)
    )

    assert stored_count == 0
