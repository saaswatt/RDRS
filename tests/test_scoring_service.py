
from contextlib import contextmanager

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import load_config
from app.database.base import Base
from app.database.models import Score
from app.services import scoring_service


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
        yield test_session

    monkeypatch.setattr(
        scoring_service,
        "get_db_session",
        mock_get_db_session,
    )

    return test_session


@pytest.fixture
def config():
    return load_config()


def test_score_detection_results_persists_score(
    isolated_database,
    config,
):
    detection_results = {
        "event_count": 35,
        "signals": {
            "rapid_modification": True,
            "mass_rename": True,
            "high_entropy": True,
        },
    }

    result = scoring_service.score_detection_results(
        detection_results,
        config=config,
    )

    assert result["threat_score"] == 95
    assert result["threat_level"] == "CRITICAL"
    assert result["triggered_signals"] == [
        "rapid_modification",
        "mass_rename",
        "high_entropy",
    ]
    assert result["score_id"] is not None

    saved_score = isolated_database.get(
        Score,
        result["score_id"],
    )

    assert saved_score is not None
    assert saved_score.threat_score == 95
    assert saved_score.threat_level == "CRITICAL"


def test_score_detection_results_handles_no_signals(
    isolated_database,
    config,
):
    detection_results = {
        "event_count": 0,
        "signals": {},
    }

    result = scoring_service.score_detection_results(
        detection_results,
        config=config,
    )

    assert result["threat_score"] == 0
    assert result["threat_level"] == "NORMAL"
    assert result["triggered_signals"] == []
    assert result["score_id"] is not None


def test_score_detection_results_rejects_invalid_input():
    with pytest.raises(TypeError):
        scoring_service.score_detection_results(
            ["not", "a", "mapping"]
        )


def test_score_detection_results_rejects_missing_signals(
    config,
):
    with pytest.raises(ValueError):
        scoring_service.score_detection_results(
            {"event_count": 10},
            config=config,
        )


def test_score_detection_results_rejects_invalid_signals(
    config,
):
    detection_results = {
        "event_count": 10,
        "signals": {
            "rapid_modification": "yes",
        },
    }

    with pytest.raises(ValueError):
        scoring_service.score_detection_results(
            detection_results,
            config=config,
        )


def test_score_detection_results_persists_only_one_record(
    isolated_database,
    config,
):
    detection_results = {
        "signals": {
            "high_entropy": True,
        },
    }

    scoring_service.score_detection_results(
        detection_results,
        config=config,
    )

    scoring_service.score_detection_results(
        detection_results,
        config=config,
    )

    records = isolated_database.scalars(
        select(Score)
    ).all()

    assert len(records) == 2
