
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import Score


class ScoreRepository:
    """
    Handles persistence and retrieval of threat-score evaluations.

    The repository receives an existing SQLAlchemy session
    and does not manage its lifecycle.
    """

    def __init__(self, session: Session):
        self.session = session

    @staticmethod
    def _validate_score(threat_score: int) -> None:
        """Validate a threat score between 0 and 100."""

        if (
            isinstance(threat_score, bool)
            or not isinstance(threat_score, int)
            or not 0 <= threat_score <= 100
        ):
            raise ValueError(
                "Threat score must be an integer between 0 and 100."
            )

    @staticmethod
    def _validate_limit(limit: int) -> None:
        """Validate a database query limit."""

        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or limit <= 0
        ):
            raise ValueError("Limit must be a positive integer.")

    def create_score(
        self,
        threat_score: int,
        threat_level: str,
        triggered_signals: list[str],
        timestamp: datetime | None = None,
        incident_id: int | None = None,
    ) -> Score:
        """
        Create and stage a threat-score record.

        The caller is responsible for committing the transaction.
        """

        self._validate_score(threat_score)

        if (
            not isinstance(threat_level, str)
            or not threat_level.strip()
        ):
            raise ValueError("Threat level cannot be empty.")

        if not isinstance(triggered_signals, list):
            raise ValueError("Triggered signals must be a list.")

        if any(
            not isinstance(signal, str) or not signal.strip()
            for signal in triggered_signals
        ):
            raise ValueError(
                "Every triggered signal must be a non-empty string."
            )

        if timestamp is None:
            timestamp = datetime.now(timezone.utc)
        elif (
            not isinstance(timestamp, datetime)
            or timestamp.tzinfo is None
            or timestamp.utcoffset() is None
        ):
            raise ValueError("Timestamp must be timezone-aware.")

        timestamp = timestamp.astimezone(timezone.utc)

        if incident_id is not None:
            if (
                isinstance(incident_id, bool)
                or not isinstance(incident_id, int)
                or incident_id <= 0
            ):
                raise ValueError(
                    "Incident ID must be a positive integer or None."
                )

        score = Score(
            threat_score=threat_score,
            threat_level=threat_level.strip().upper(),
            triggered_signals=[
                signal.strip() for signal in triggered_signals
            ],
            timestamp=timestamp,
            incident_id=incident_id,
        )

        self.session.add(score)
        self.session.flush()

        return score

    def get_score_by_id(self, score_id: int) -> Score | None:
        """Retrieve a threat-score record by its ID."""

        if (
            isinstance(score_id, bool)
            or not isinstance(score_id, int)
            or score_id <= 0
        ):
            raise ValueError("Score ID must be a positive integer.")

        statement = select(Score).where(Score.id == score_id)

        return self.session.scalars(statement).first()

    def get_recent_scores(self, limit: int = 100) -> list[Score]:
        """Retrieve recent threat-score evaluations, newest first."""

        self._validate_limit(limit)

        statement = (
            select(Score)
            .order_by(
                Score.timestamp.desc(),
                Score.id.desc()
            )
            .limit(limit)
        )

        return list(self.session.scalars(statement).all())

    def get_scores_by_incident(
        self,
        incident_id: int,
        limit: int = 100,
    ) -> list[Score]:
        """Retrieve score evaluations associated with an incident."""

        if (
            isinstance(incident_id, bool)
            or not isinstance(incident_id, int)
            or incident_id <= 0
        ):
            raise ValueError(
                "Incident ID must be a positive integer."
            )

        self._validate_limit(limit)

        statement = (
            select(Score)
            .where(Score.incident_id == incident_id)
            .order_by(
                Score.timestamp.desc(),
                Score.id.desc()
            )
            .limit(limit)
        )

        return list(self.session.scalars(statement).all())
