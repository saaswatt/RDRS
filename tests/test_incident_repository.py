
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database.base import Base
from app.database.models import Incident
from app.database.repositories.incident_repository import (
    IncidentRepository,
)


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
def repository(test_session):
    return IncidentRepository(test_session)


def create_test_incident(repository, **overrides):
    data = {
        "incident_reference": "RDRS-INC-0001",
        "title": "Suspicious file activity",
        "description": "Multiple suspicious filesystem events detected.",
        "severity": "CRITICAL",
        "threat_score": 95,
        "affected_files": [
            "data/sandbox/file1.txt",
            "data/sandbox/file2.txt",
        ],
    }

    data.update(overrides)

    return repository.create_incident(**data)


def test_create_incident(repository, test_session):
    incident = create_test_incident(repository)

    assert incident.id is not None
    assert incident.incident_reference == "RDRS-INC-0001"
    assert incident.title == "Suspicious file activity"
    assert incident.severity == "CRITICAL"
    assert incident.threat_score == 95
    assert incident.status == "OPEN"
    assert len(incident.affected_files) == 2

    saved_incident = test_session.get(Incident, incident.id)

    assert saved_incident is not None


def test_create_incident_normalizes_values(repository):
    incident = create_test_incident(
        repository,
        incident_reference="  RDRS-INC-0002  ",
        title="  Test incident  ",
        severity="critical",
        status="open",
        affected_files=["  data/sandbox/test.txt  "],
    )

    assert incident.incident_reference == "RDRS-INC-0002"
    assert incident.title == "Test incident"
    assert incident.severity == "CRITICAL"
    assert incident.status == "OPEN"
    assert incident.affected_files == ["data/sandbox/test.txt"]


def test_create_incident_normalizes_timestamp(repository):
    timestamp = datetime(
        2026, 11, 10, 12, 0, tzinfo=timezone.utc
    )

    incident = create_test_incident(
        repository,
        created_at=timestamp,
    )

    assert incident.created_at == timestamp
    assert incident.updated_at == timestamp


@pytest.mark.parametrize(
    "field,value",
    [
        ("incident_reference", ""),
        ("title", ""),
        ("description", ""),
        ("severity", ""),
        ("status", ""),
    ],
)
def test_create_incident_rejects_empty_required_fields(
    repository,
    field,
    value,
):
    with pytest.raises(ValueError):
        create_test_incident(repository, **{field: value})


@pytest.mark.parametrize(
    "threat_score",
    [-1, 101, True, 50.5, "50"],
)
def test_create_incident_rejects_invalid_threat_score(
    repository,
    threat_score,
):
    with pytest.raises(ValueError):
        create_test_incident(
            repository,
            threat_score=threat_score,
        )


def test_create_incident_rejects_invalid_affected_files(
    repository,
):
    with pytest.raises(ValueError):
        create_test_incident(
            repository,
            affected_files="data/sandbox/file.txt",
        )

    with pytest.raises(ValueError):
        create_test_incident(
            repository,
            affected_files=["valid.txt", ""],
        )


def test_create_incident_rejects_naive_timestamp(repository):
    with pytest.raises(ValueError):
        create_test_incident(
            repository,
            created_at=datetime(2026, 11, 10, 12, 0),
        )


def test_create_incident_rejects_invalid_process_id(repository):
    for process_id in [0, -1, True, 1.5]:
        with pytest.raises(ValueError):
            create_test_incident(
                repository,
                suspect_process_id=process_id,
            )


def test_get_incident_by_id(repository):
    incident = create_test_incident(repository)

    retrieved = repository.get_incident_by_id(incident.id)

    assert retrieved is not None
    assert retrieved.incident_reference == incident.incident_reference


def test_get_incident_by_id_returns_none_for_missing_record(
    repository,
):
    assert repository.get_incident_by_id(9999) is None


def test_get_incident_by_reference(repository):
    incident = create_test_incident(repository)

    retrieved = repository.get_incident_by_reference(
        "RDRS-INC-0001"
    )

    assert retrieved is not None
    assert retrieved.id == incident.id


def test_get_incident_by_reference_returns_none_for_missing_record(
    repository,
):
    assert (
        repository.get_incident_by_reference("RDRS-INC-MISSING")
        is None
    )


def test_get_recent_incidents(repository):
    first = create_test_incident(
        repository,
        incident_reference="RDRS-INC-0001",
    )

    second = create_test_incident(
        repository,
        incident_reference="RDRS-INC-0002",
    )

    results = repository.get_recent_incidents(limit=2)

    assert len(results) == 2
    assert results[0].id == second.id
    assert results[1].id == first.id


def test_get_incidents_by_status(repository):
    create_test_incident(
        repository,
        incident_reference="RDRS-INC-0001",
        status="OPEN",
    )

    resolved = create_test_incident(
        repository,
        incident_reference="RDRS-INC-0002",
        status="RESOLVED",
    )

    results = repository.get_incidents_by_status("resolved")

    assert len(results) == 1
    assert results[0].id == resolved.id
    assert results[0].status == "RESOLVED"


def test_duplicate_incident_reference_is_rejected(
    repository,
):
    create_test_incident(repository)

    with pytest.raises(IntegrityError):
        create_test_incident(repository)

    repository.session.rollback()


@pytest.mark.parametrize("limit", [0, -1, True, 1.5])
def test_recent_incidents_rejects_invalid_limit(
    repository,
    limit,
):
    with pytest.raises(ValueError):
        repository.get_recent_incidents(limit=limit)


def test_get_incident_by_id_rejects_invalid_id(repository):
    for incident_id in [0, -1, True, 1.5]:
        with pytest.raises(ValueError):
            repository.get_incident_by_id(incident_id)


def test_get_incidents_by_status_rejects_empty_status(
    repository,
):
    with pytest.raises(ValueError):
        repository.get_incidents_by_status("")
