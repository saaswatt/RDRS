
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import Incident


class IncidentRepository:
    """
    Handles persistence and retrieval of security incidents.

    The repository receives an existing SQLAlchemy session
    and does not manage its lifecycle.
    """

    def __init__(self, session: Session):
        self.session = session

    @staticmethod
    def _validate_limit(limit: int) -> None:
        """Validate a database query limit."""

        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or limit <= 0
        ):
            raise ValueError("Limit must be a positive integer.")

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

    def create_incident(
        self,
        incident_reference: str,
        title: str,
        description: str,
        severity: str,
        threat_score: int,
        affected_files: list[str],
        status: str = "OPEN",
        suspect_process_id: int | None = None,
        created_at: datetime | None = None,
    ) -> Incident:
        """
        Create and stage a security incident.

        The caller is responsible for committing the transaction.
        """

        if (
            not isinstance(incident_reference, str)
            or not incident_reference.strip()
        ):
            raise ValueError(
                "Incident reference cannot be empty."
            )

        if (
            not isinstance(title, str)
            or not title.strip()
        ):
            raise ValueError("Incident title cannot be empty.")

        if (
            not isinstance(description, str)
            or not description.strip()
        ):
            raise ValueError(
                "Incident description cannot be empty."
            )

        if (
            not isinstance(severity, str)
            or not severity.strip()
        ):
            raise ValueError("Incident severity cannot be empty.")

        self._validate_score(threat_score)

        if not isinstance(affected_files, list):
            raise ValueError(
                "Affected files must be provided as a list."
            )

        if any(
            not isinstance(file_path, str) or not file_path.strip()
            for file_path in affected_files
        ):
            raise ValueError(
                "Every affected file path must be a non-empty string."
            )

        if (
            not isinstance(status, str)
            or not status.strip()
        ):
            raise ValueError("Incident status cannot be empty.")

        if suspect_process_id is not None:
            if (
                isinstance(suspect_process_id, bool)
                or not isinstance(suspect_process_id, int)
                or suspect_process_id <= 0
            ):
                raise ValueError(
                    "Suspect process ID must be a positive integer or None."
                )

        if created_at is None:
            created_at = datetime.now(timezone.utc)
        elif (
            not isinstance(created_at, datetime)
            or created_at.tzinfo is None
            or created_at.utcoffset() is None
        ):
            raise ValueError(
                "Incident creation timestamp must be timezone-aware."
            )

        created_at = created_at.astimezone(timezone.utc)

        incident = Incident(
            incident_reference=incident_reference.strip(),
            title=title.strip(),
            description=description.strip(),
            severity=severity.strip().upper(),
            threat_score=threat_score,
            affected_files=[
                file_path.strip() for file_path in affected_files
            ],
            status=status.strip().upper(),
            suspect_process_id=suspect_process_id,
            created_at=created_at,
            updated_at=created_at,
        )

        self.session.add(incident)
        self.session.flush()

        return incident

    def get_incident_by_id(
        self,
        incident_id: int,
    ) -> Incident | None:
        """Retrieve an incident by its database ID."""

        if (
            isinstance(incident_id, bool)
            or not isinstance(incident_id, int)
            or incident_id <= 0
        ):
            raise ValueError(
                "Incident ID must be a positive integer."
            )

        statement = select(Incident).where(
            Incident.id == incident_id
        )

        return self.session.scalars(statement).first()

    def get_incident_by_reference(
        self,
        incident_reference: str,
    ) -> Incident | None:
        """Retrieve an incident by its unique reference."""

        if (
            not isinstance(incident_reference, str)
            or not incident_reference.strip()
        ):
            raise ValueError(
                "Incident reference cannot be empty."
            )

        statement = select(Incident).where(
            Incident.incident_reference == incident_reference.strip()
        )

        return self.session.scalars(statement).first()

    def get_recent_incidents(
        self,
        limit: int = 100,
    ) -> list[Incident]:
        """Retrieve recent incidents, newest first."""

        self._validate_limit(limit)

        statement = (
            select(Incident)
            .order_by(
                Incident.created_at.desc(),
                Incident.id.desc(),
            )
            .limit(limit)
        )

        return list(self.session.scalars(statement).all())

    def get_incidents_by_status(
        self,
        status: str,
        limit: int = 100,
    ) -> list[Incident]:
        """Retrieve incidents filtered by status, newest first."""

        if not isinstance(status, str) or not status.strip():
            raise ValueError("Incident status cannot be empty.")

        self._validate_limit(limit)

        statement = (
            select(Incident)
            .where(Incident.status == status.strip().upper())
            .order_by(
                Incident.created_at.desc(),
                Incident.id.desc(),
            )
            .limit(limit)
        )

        return list(self.session.scalars(statement).all())
