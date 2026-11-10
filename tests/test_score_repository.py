
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.database.base import Base
from app.database.models import Incident, Score
from app.database.repositories.score_repository import ScoreRepository


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")

    Base.metadata.create_all(bind=engine)

    TestingSessionLocal = sessionmaker(
        bind=engine,
        class_=Session,
        autoflush=False,
        expire_on_commit=False,
    )

    session = TestingSessionLocal()

    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture
def repository(db_session):
    return ScoreRepository(db_session)


@pytest.fixture
def incident(db_session):
    record = Incident(
        incident_reference="TEST-INC-001",
        title="Test incident",
        description="Test incident for score repository.",
        severity="CRITICAL",
        threat_score=85,
        status="OPEN",
        affected_files=[],
    )

    db_session.add(record)
    db_session.flush()

    return record


def test_create_score(repository, db_session):
    score = repository.create_score(
        threat_score=85,
        threat_level="critical",
        triggered_signals=[
            "rapid_modification",
            "mass_rename",
        ],
    )

    assert score.id is not None
    assert score.threat_score == 85
    assert score.threat_level == "CRITICAL"
    assert score.triggered_signals == [
        "rapid_modification",
        "mass_rename",
    ]

    assert db_session.get(Score, score.id) is score


def test_create_score_normalizes_timestamp(repository):
    timestamp = datetime(
        2026, 11, 10, 12, 0, tzinfo=timezone(timedelta(hours=5, minutes=30))
    )

    score = repository.create_score(
        threat_score=40,
        threat_level="normal",
        triggered_signals=[],
        timestamp=timestamp,
    )

    assert score.timestamp.utcoffset() == timedelta(0)
    assert score.timestamp.hour == 6
    assert score.timestamp.minute == 30


@pytest.mark.parametrize("invalid_score", [-1, 101, True, 50.5, "50"])
def test_rejects_invalid_threat_score(repository, invalid_score):
    with pytest.raises(ValueError):
        repository.create_score(
            threat_score=invalid_score,
            threat_level="NORMAL",
            triggered_signals=[],
        )


def test_rejects_empty_threat_level(repository):
    with pytest.raises(ValueError):
        repository.create_score(
            threat_score=50,
            threat_level=" ",
            triggered_signals=[],
        )


def test_rejects_invalid_triggered_signals(repository):
    with pytest.raises(ValueError):
        repository.create_score(
            threat_score=50,
            threat_level="WARNING",
            triggered_signals="rapid_modification",
        )

    with pytest.raises(ValueError):
        repository.create_score(
            threat_score=50,
            threat_level="WARNING",
            triggered_signals=["rapid_modification", ""],
        )


def test_rejects_naive_timestamp(repository):
    with pytest.raises(ValueError):
        repository.create_score(
            threat_score=50,
            threat_level="WARNING",
            triggered_signals=[],
            timestamp=datetime(2026, 11, 10, 12, 0),
        )


def test_create_score_with_incident(repository, incident):
    score = repository.create_score(
        threat_score=85,
        threat_level="CRITICAL",
        triggered_signals=["rapid_modification"],
        incident_id=incident.id,
    )

    assert score.incident_id == incident.id


def test_rejects_invalid_incident_id(repository):
    with pytest.raises(ValueError):
        repository.create_score(
            threat_score=50,
            threat_level="WARNING",
            triggered_signals=[],
            incident_id=0,
        )


def test_get_score_by_id(repository):
    created = repository.create_score(
        threat_score=60,
        threat_level="WARNING",
        triggered_signals=["mass_rename"],
    )

    retrieved = repository.get_score_by_id(created.id)

    assert retrieved is not None
    assert retrieved.id == created.id
    assert retrieved.threat_score == 60


def test_get_score_by_id_returns_none_for_missing_record(repository):
    assert repository.get_score_by_id(999) is None


def test_get_recent_scores(repository):
    older = repository.create_score(
        threat_score=30,
        threat_level="NORMAL",
        triggered_signals=[],
        timestamp=datetime(2026, 11, 9, tzinfo=timezone.utc),
    )

    newer = repository.create_score(
        threat_score=85,
        threat_level="CRITICAL",
        triggered_signals=["rapid_modification"],
        timestamp=datetime(2026, 11, 10, tzinfo=timezone.utc),
    )

    results = repository.get_recent_scores()

    assert [score.id for score in results] == [
        newer.id,
        older.id,
    ]


def test_get_scores_by_incident(repository, incident):
    first = repository.create_score(
        threat_score=75,
        threat_level="CRITICAL",
        triggered_signals=["mass_rename"],
        incident_id=incident.id,
        timestamp=datetime(2026, 11, 9, tzinfo=timezone.utc),
    )

    second = repository.create_score(
        threat_score=85,
        threat_level="CRITICAL",
        triggered_signals=["rapid_modification"],
        incident_id=incident.id,
        timestamp=datetime(2026, 11, 10, tzinfo=timezone.utc),
    )

    results = repository.get_scores_by_incident(incident.id)

    assert [score.id for score in results] == [
        second.id,
        first.id,
    ]


@pytest.mark.parametrize("invalid_limit", [0, -1, True, 1.5])
def test_rejects_invalid_limits(repository, invalid_limit):
    with pytest.raises(ValueError):
        repository.get_recent_scores(limit=invalid_limit)


def test_rejects_invalid_score_id(repository):
    with pytest.raises(ValueError):
        repository.get_score_by_id(0)


def test_rejects_invalid_incident_id_for_query(repository):
    with pytest.raises(ValueError):
        repository.get_scores_by_incident(0)
