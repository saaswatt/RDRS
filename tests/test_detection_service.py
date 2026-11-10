
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.core.config import load_config
from app.services import detection_service


def make_event(timestamp, event_type="MODIFIED", is_directory=False):
    return SimpleNamespace(
        timestamp=timestamp,
        event_type=event_type,
        source_path="data/sandbox/test.txt",
        destination_path=None,
        file_extension=".txt",
        entropy=7.5,
        is_directory=is_directory,
    )


@pytest.fixture
def config():
    return load_config()


def setup_detection_mocks(monkeypatch, events):
    class FakeRepository:
        def __init__(self, session):
            self.session = session

        def get_events_since(self, timestamp):
            return events

    @contextmanager
    def fake_get_db_session():
        yield object()

    monkeypatch.setattr(
        detection_service,
        "EventRepository",
        FakeRepository,
    )
    monkeypatch.setattr(
        detection_service,
        "get_db_session",
        fake_get_db_session,
    )


def test_only_events_inside_window_are_analyzed(monkeypatch, config):
    current_time = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)

    events = [
        make_event(current_time - timedelta(seconds=30)),
        make_event(current_time - timedelta(seconds=60)),
        make_event(current_time - timedelta(seconds=90)),
        make_event(current_time + timedelta(seconds=10)),
    ]

    setup_detection_mocks(monkeypatch, events)

    result = detection_service.run_filesystem_detection(
        config=config,
        current_time=current_time,
    )

    assert result["event_count"] == 2
    assert result["window_end"] == current_time.isoformat()


def test_empty_detection_window(monkeypatch, config):
    current_time = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)

    setup_detection_mocks(monkeypatch, [])

    result = detection_service.run_filesystem_detection(
        config=config,
        current_time=current_time,
    )

    assert result["event_count"] == 0
    assert result["modified_count"] == 0
    assert not any(result["signals"].values())


def test_directory_events_are_excluded(monkeypatch, config):
    current_time = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)

    events = [
        make_event(
            current_time - timedelta(seconds=10),
            is_directory=True,
        ),
        make_event(
            current_time - timedelta(seconds=20),
            is_directory=False,
        ),
    ]

    setup_detection_mocks(monkeypatch, events)

    result = detection_service.run_filesystem_detection(
        config=config,
        current_time=current_time,
    )

    assert result["event_count"] == 1
    assert result["modified_count"] == 1


def test_naive_database_timestamps_are_treated_as_utc(
    monkeypatch,
    config,
):
    current_time = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)

    naive_timestamp = (
        current_time - timedelta(seconds=30)
    ).replace(tzinfo=None)

    setup_detection_mocks(
        monkeypatch,
        [make_event(naive_timestamp)],
    )

    result = detection_service.run_filesystem_detection(
        config=config,
        current_time=current_time,
    )

    assert result["event_count"] == 1


def test_invalid_current_time_is_rejected(config):
    with pytest.raises(ValueError, match="timezone-aware"):
        detection_service.run_filesystem_detection(
            config=config,
            current_time=datetime(2026, 11, 10, 12, 0),
        )


def test_database_failure_is_propagated(monkeypatch, config):
    class FailingRepository:
        def __init__(self, session):
            pass

        def get_events_since(self, timestamp):
            raise RuntimeError("Database unavailable")

    @contextmanager
    def fake_get_db_session():
        yield object()

    monkeypatch.setattr(
        detection_service,
        "EventRepository",
        FailingRepository,
    )
    monkeypatch.setattr(
        detection_service,
        "get_db_session",
        fake_get_db_session,
    )

    current_time = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)

    with pytest.raises(RuntimeError, match="Database unavailable"):
        detection_service.run_filesystem_detection(
            config=config,
            current_time=current_time,
        )
