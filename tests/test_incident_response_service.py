
from contextlib import contextmanager
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, select, func
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import load_config
from app.database.base import Base
from app.database.models import Alert, Incident, Score
from app.services import incident_response_service


@pytest.fixture
def test_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    Base.metadata.create_all(bind=engine)

    TestingSessionLocal = sessionmaker(
        bind=engine,
        autoflush=False,
        expire_on_commit=False,
    )

    with TestingSessionLocal() as session:
        yield session

    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture
def isolated_database(test_session, monkeypatch):
    @contextmanager
    def mock_get_db_session():
        with test_session.begin():
            yield test_session

    monkeypatch.setattr(
        incident_response_service,
        "get_db_session",
        mock_get_db_session,
    )

    return test_session


@pytest.fixture
def config():
    return load_config()


def test_critical_detection_creates_incident_score_and_alert(
    isolated_database,
    config,
):
    detection_results = {
        "event_count": 35,
        "affected_files": [
            "data/sandbox/file1.txt",
            "data/sandbox/file2.txt",
        ],
        "signals": {
            "rapid_modification": True,
            "mass_rename": True,
            "high_entropy": True,
        },
    }

    result = incident_response_service.process_detection_response(
        detection_results,
        config=config,
    )

    assert result["threat_score"] == 95
    assert result["threat_level"] == "CRITICAL"
    assert result["score_id"] is not None
    assert result["incident_id"] is not None
    assert result["incident_reference"] is not None
    assert result["alert_id"] is not None

    incident = isolated_database.get(
        Incident,
        result["incident_id"],
    )

    score = isolated_database.get(
        Score,
        result["score_id"],
    )

    alert = isolated_database.get(
        Alert,
        result["alert_id"],
    )

    assert incident is not None
    assert incident.threat_score == 95
    assert incident.severity == "CRITICAL"
    assert incident.status == "OPEN"
    assert incident.affected_files == detection_results["affected_files"]

    assert score is not None
    assert score.threat_score == 95
    assert score.incident_id == incident.id

    assert alert is not None
    assert alert.threat_score == 95
    assert alert.incident_id == incident.id
    assert alert.alert_type == "THREAT_DETECTED"


def test_normal_detection_creates_only_score(
    isolated_database,
    config,
):
    detection_results = {
        "signals": {
            "high_entropy": True,
        },
    }

    result = incident_response_service.process_detection_response(
        detection_results,
        config=config,
    )

    assert result["threat_score"] == 25
    assert result["threat_level"] == "NORMAL"
    assert result["score_id"] is not None
    assert result["incident_id"] is None
    assert result["incident_reference"] is None
    assert result["alert_id"] is None

    assert isolated_database.scalar(
        select(func.count()).select_from(Score)
    ) == 1

    assert isolated_database.scalar(
        select(func.count()).select_from(Incident)
    ) == 0

    assert isolated_database.scalar(
        select(func.count()).select_from(Alert)
    ) == 0


def test_warning_detection_creates_only_score(
    isolated_database,
    config,
):
    detection_results = {
        "signals": {
            "rapid_modification": True,
            "high_entropy": True,
        },
    }

    result = incident_response_service.process_detection_response(
        detection_results,
        config=config,
    )

    assert result["threat_score"] == 65
    assert result["threat_level"] == "WARNING"
    assert result["score_id"] is not None
    assert result["incident_id"] is None
    assert result["alert_id"] is None

    assert isolated_database.scalar(
        select(func.count()).select_from(Score)
    ) == 1

    assert isolated_database.scalar(
        select(func.count()).select_from(Incident)
    ) == 0

    assert isolated_database.scalar(
        select(func.count()).select_from(Alert)
    ) == 0


def test_critical_detection_uses_supplied_timestamp(
    isolated_database,
    config,
):
    supplied_timestamp = datetime(
        2026, 11, 10, 12, 0, tzinfo=timezone.utc
    )

    result = incident_response_service.process_detection_response(
        {
            "affected_files": [],
            "signals": {
                "rapid_modification": True,
                "mass_rename": True,
                "high_entropy": True,
            },
        },
        config=config,
        timestamp=supplied_timestamp,
    )

    incident = isolated_database.get(
        Incident,
        result["incident_id"],
    )

    score = isolated_database.get(
        Score,
        result["score_id"],
    )

    alert = isolated_database.get(
        Alert,
        result["alert_id"],
    )

    assert incident is not None
    assert score is not None
    assert alert is not None

    # SQLite returns stored UTC timestamps without timezone information.
    for stored_timestamp in (
        incident.created_at,
        score.timestamp,
        alert.timestamp,
    ):
        if stored_timestamp.tzinfo is None:
            stored_timestamp = stored_timestamp.replace(
                tzinfo=timezone.utc
            )
        else:
            stored_timestamp = stored_timestamp.astimezone(
                timezone.utc
            )

        assert stored_timestamp == supplied_timestamp


def test_service_rejects_invalid_detection_results():
    with pytest.raises(TypeError):
        incident_response_service.process_detection_response(
            ["invalid"]
        )


def test_service_rejects_missing_signals(config):
    with pytest.raises(ValueError):
        incident_response_service.process_detection_response(
            {"event_count": 10},
            config=config,
        )


def test_service_rejects_invalid_affected_files(config):
    with pytest.raises(ValueError):
        incident_response_service.process_detection_response(
            {
                "signals": {},
                "affected_files": ["valid.txt", ""],
            },
            config=config,
        )


def test_service_rejects_naive_timestamp(config):
    with pytest.raises(ValueError):
        incident_response_service.process_detection_response(
            {"signals": {}},
            config=config,
            timestamp=datetime(2026, 11, 10, 12, 0),
        )


def test_failed_alert_creation_rolls_back_entire_transaction(
    isolated_database,
    config,
    monkeypatch,
):
    def fail_alert_creation(*args, **kwargs):
        raise RuntimeError("Simulated alert creation failure.")

    monkeypatch.setattr(
        incident_response_service.AlertRepository,
        "create_alert",
        fail_alert_creation,
    )

    detection_results = {
        "affected_files": ["data/sandbox/test.txt"],
        "signals": {
            "rapid_modification": True,
            "mass_rename": True,
            "high_entropy": True,
        },
    }

    with pytest.raises(
        RuntimeError,
        match="Simulated alert creation failure",
    ):
        incident_response_service.process_detection_response(
            detection_results,
            config=config,
        )

    assert isolated_database.scalar(
        select(func.count()).select_from(Incident)
    ) == 0

    assert isolated_database.scalar(
        select(func.count()).select_from(Score)
    ) == 0

    assert isolated_database.scalar(
        select(func.count()).select_from(Alert)
    ) == 0


def test_repeated_critical_detections_create_separate_incidents(
    isolated_database,
    config,
):
    detection_results = {
        "signals": {
            "rapid_modification": True,
            "mass_rename": True,
            "high_entropy": True,
        },
    }

    first_result = incident_response_service.process_detection_response(
        detection_results,
        config=config,
    )

    second_result = incident_response_service.process_detection_response(
        detection_results,
        config=config,
    )

    assert first_result["incident_id"] != second_result["incident_id"]
    assert (
        first_result["incident_reference"]
        != second_result["incident_reference"]
    )

    assert isolated_database.scalar(
        select(func.count()).select_from(Incident)
    ) == 2

    assert isolated_database.scalar(
        select(func.count()).select_from(Score)
    ) == 2

    assert isolated_database.scalar(
        select(func.count()).select_from(Alert)
    ) == 2
