
from datetime import datetime, timezone
from unittest.mock import Mock

import pytest

from app.core.config import load_config
from app.services import detection_coordinator
from app.services.detection_coordinator import DetectionCoordinator


@pytest.fixture
def config():
    return load_config()


@pytest.fixture
def coordinator(config):
    return DetectionCoordinator(config)


@pytest.fixture
def current_time():
    return datetime(2026, 11, 10, 18, 0, tzinfo=timezone.utc)


def make_detection_results(event_ids=None, signals=None):
    return {
        "event_count": len(event_ids or []),
        "event_ids": event_ids or [],
        "affected_files": ["data/sandbox/test.txt"],
        "signals": signals or {
            "rapid_modification": False,
            "mass_rename": False,
            "high_entropy": False,
        },
    }


def test_first_detection_result_is_processed(
    coordinator, current_time, monkeypatch
):
    detection_results = make_detection_results(event_ids=[1, 2])

    detection_mock = Mock(return_value=detection_results)
    response_mock = Mock(return_value={
        "threat_level": "NORMAL",
        "threat_score": 0,
    })

    monkeypatch.setattr(
        detection_coordinator,
        "run_filesystem_detection",
        detection_mock,
    )
    monkeypatch.setattr(
        detection_coordinator,
        "process_detection_response",
        response_mock,
    )

    result = coordinator.run_cycle(current_time)

    assert result["threat_level"] == "NORMAL"
    detection_mock.assert_called_once()
    response_mock.assert_called_once()


def test_unchanged_result_is_not_processed_twice(
    coordinator, current_time, monkeypatch
):
    detection_results = make_detection_results(event_ids=[1, 2])

    monkeypatch.setattr(
        detection_coordinator,
        "run_filesystem_detection",
        Mock(return_value=detection_results),
    )

    response_mock = Mock(return_value={
        "threat_level": "NORMAL",
        "threat_score": 0,
    })

    monkeypatch.setattr(
        detection_coordinator,
        "process_detection_response",
        response_mock,
    )

    coordinator.run_cycle(current_time)
    second_result = coordinator.run_cycle(current_time)

    assert second_result is None
    assert response_mock.call_count == 1


def test_changed_event_ids_are_processed(
    coordinator, current_time, monkeypatch
):
    first_result = make_detection_results(event_ids=[1, 2])
    second_result = make_detection_results(event_ids=[1, 2, 3])

    detection_mock = Mock(
        side_effect=[first_result, second_result]
    )

    response_mock = Mock(return_value={
        "threat_level": "NORMAL",
        "threat_score": 0,
    })

    monkeypatch.setattr(
        detection_coordinator,
        "run_filesystem_detection",
        detection_mock,
    )
    monkeypatch.setattr(
        detection_coordinator,
        "process_detection_response",
        response_mock,
    )

    coordinator.run_cycle(current_time)
    coordinator.run_cycle(current_time)

    assert response_mock.call_count == 2


def test_failed_response_can_be_retried(
    coordinator, current_time, monkeypatch
):
    detection_results = make_detection_results(event_ids=[1, 2])

    monkeypatch.setattr(
        detection_coordinator,
        "run_filesystem_detection",
        Mock(return_value=detection_results),
    )

    response_mock = Mock(
        side_effect=[
            RuntimeError("Database unavailable"),
            {
                "threat_level": "NORMAL",
                "threat_score": 0,
            },
        ]
    )

    monkeypatch.setattr(
        detection_coordinator,
        "process_detection_response",
        response_mock,
    )

    with pytest.raises(RuntimeError):
        coordinator.run_cycle(current_time)

    result = coordinator.run_cycle(current_time)

    assert result["threat_level"] == "NORMAL"
    assert response_mock.call_count == 2


def test_naive_timestamp_is_rejected(coordinator):
    naive_time = datetime(2026, 11, 10, 18, 0)

    with pytest.raises(ValueError):
        coordinator.run_cycle(naive_time)
