
from datetime import datetime, timedelta, timezone

import pytest

from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database.base import Base
from app.database.models import Alert
from app.database.repositories.alert_repository import AlertRepository


@pytest.fixture
def db_session():
    """Create an isolated in-memory SQLite database."""

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

    session = TestingSessionLocal()

    yield session

    session.close()
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture
def repository(db_session):
    return AlertRepository(db_session)


def create_test_alert(repository, **overrides):
    """Create an alert using valid default values."""

    values = {
        "alert_type": "high_entropy",
        "severity": "warning",
        "message": "High entropy detected in a modified file.",
        "threat_score": 55,
        "file_path": "data/sandbox/test.txt",
    }

    values.update(overrides)

    return repository.create_alert(**values)


def test_create_alert(repository, db_session):
    alert = create_test_alert(repository)

    assert alert.id is not None
    assert alert.alert_type == "HIGH_ENTROPY"
    assert alert.severity == "WARNING"
    assert alert.threat_score == 55
    assert alert.file_path == "data/sandbox/test.txt"

    assert db_session.get(Alert, alert.id) is not None


def test_create_alert_normalizes_values(repository):
    alert = create_test_alert(
        repository,
        alert_type="  rapid_modification  ",
        severity="  critical  ",
        message="  Suspicious activity detected.  ",
        file_path="  data/sandbox/sample.txt  ",
    )

    assert alert.alert_type == "RAPID_MODIFICATION"
    assert alert.severity == "CRITICAL"
    assert alert.message == "Suspicious activity detected."
    assert alert.file_path == "data/sandbox/sample.txt"


@pytest.mark.parametrize(
    "field",
    ["alert_type", "severity", "message"],
)
def test_create_alert_rejects_empty_required_fields(
    repository,
    field,
):
    values = {
        "alert_type": "HIGH_ENTROPY",
        "severity": "WARNING",
        "message": "Test alert",
        "threat_score": 50,
    }

    values[field] = "   "

    with pytest.raises(ValueError):
        repository.create_alert(**values)


@pytest.mark.parametrize(
    "score",
    [-1, 101, True, 50.5, "50"],
)
def test_create_alert_rejects_invalid_threat_score(
    repository,
    score,
):
    with pytest.raises(ValueError):
        create_test_alert(
            repository,
            threat_score=score,
        )


@pytest.mark.parametrize(
    "file_path",
    ["", "   ", 123],
)
def test_create_alert_rejects_invalid_file_path(
    repository,
    file_path,
):
    with pytest.raises(ValueError):
        create_test_alert(
            repository,
            file_path=file_path,
        )


@pytest.mark.parametrize(
    "field",
    ["event_id", "process_id", "incident_id"],
)
@pytest.mark.parametrize(
    "invalid_id",
    [0, -1, True, 1.5, "1"],
)
def test_create_alert_rejects_invalid_foreign_key_ids(
    repository,
    field,
    invalid_id,
):
    with pytest.raises(ValueError):
        create_test_alert(
            repository,
            **{field: invalid_id},
        )


def test_create_alert_normalizes_timestamp(repository):
    supplied_time = datetime(
        2026, 11, 10, 12, 0, 0,
        tzinfo=timezone(timedelta(hours=5, minutes=30)),
    )

    alert = create_test_alert(
        repository,
        timestamp=supplied_time,
    )

    assert alert.timestamp.utcoffset() == timedelta(0)
    assert alert.timestamp.hour == 6
    assert alert.timestamp.minute == 30


def test_create_alert_rejects_naive_timestamp(repository):
    naive_time = datetime(2026, 11, 10, 12, 0, 0)

    with pytest.raises(ValueError):
        create_test_alert(
            repository,
            timestamp=naive_time,
        )


def test_create_alert_defaults_timestamp_to_utc(repository):
    before = datetime.now(timezone.utc)

    alert = create_test_alert(repository)

    after = datetime.now(timezone.utc)

    assert before <= alert.timestamp <= after
    assert alert.timestamp.utcoffset() == timedelta(0)


def test_get_alert_by_id(repository):
    alert = create_test_alert(repository)

    result = repository.get_alert_by_id(alert.id)

    assert result is not None
    assert result.id == alert.id


def test_get_alert_by_id_returns_none_for_missing_record(repository):
    assert repository.get_alert_by_id(9999) is None


@pytest.mark.parametrize("alert_id", [0, -1, True, 1.5, "1"])
def test_get_alert_by_id_rejects_invalid_id(
    repository,
    alert_id,
):
    with pytest.raises(ValueError):
        repository.get_alert_by_id(alert_id)


def test_get_recent_alerts(repository):
    first = create_test_alert(
        repository,
        timestamp=datetime(2026, 11, 10, 10, 0, tzinfo=timezone.utc),
    )

    second = create_test_alert(
        repository,
        timestamp=datetime(2026, 11, 10, 11, 0, tzinfo=timezone.utc),
    )

    results = repository.get_recent_alerts()

    assert len(results) == 2
    assert results[0].id == second.id
    assert results[1].id == first.id


@pytest.mark.parametrize("limit", [0, -1, True, 1.5])
def test_get_recent_alerts_rejects_invalid_limit(
    repository,
    limit,
):
    with pytest.raises(ValueError):
        repository.get_recent_alerts(limit=limit)


def test_get_alerts_by_severity(repository):
    warning = create_test_alert(
        repository,
        severity="WARNING",
    )

    create_test_alert(
        repository,
        severity="NORMAL",
    )

    critical = create_test_alert(
        repository,
        severity="CRITICAL",
    )

    results = repository.get_alerts_by_severity("critical")

    assert len(results) == 1
    assert results[0].id == critical.id
    assert results[0].severity == "CRITICAL"


def test_get_alerts_by_severity_normalizes_input(repository):
    alert = create_test_alert(
        repository,
        severity="WARNING",
    )

    results = repository.get_alerts_by_severity("  warning  ")

    assert len(results) == 1
    assert results[0].id == alert.id


def test_get_alerts_by_severity_rejects_empty_severity(repository):
    with pytest.raises(ValueError):
        repository.get_alerts_by_severity("   ")


def test_get_alerts_by_severity_rejects_invalid_limit(repository):
    with pytest.raises(ValueError):
        repository.get_alerts_by_severity(
            "WARNING",
            limit=0,
        )


def test_get_alerts_by_incident(repository):
    first = create_test_alert(
        repository,
        incident_id=10,
    )

    create_test_alert(
        repository,
        incident_id=20,
    )

    second = create_test_alert(
        repository,
        incident_id=10,
    )

    results = repository.get_alerts_by_incident(10)

    assert len(results) == 2
    assert results[0].id == second.id
    assert results[1].id == first.id


def test_get_alerts_by_incident_returns_empty_list(repository):
    assert repository.get_alerts_by_incident(9999) == []


def test_get_alerts_by_incident_rejects_invalid_id(repository):
    with pytest.raises(ValueError):
        repository.get_alerts_by_incident(-1)


def test_get_alerts_by_incident_rejects_none(repository):
    with pytest.raises(ValueError):
        repository.get_alerts_by_incident(None)


def test_get_alerts_by_incident_rejects_invalid_limit(repository):
    with pytest.raises(ValueError):
        repository.get_alerts_by_incident(
            10,
            limit=0,
        )
