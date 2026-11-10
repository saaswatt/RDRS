
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import Alert


class AlertRepository:
    """
    Handles persistence and retrieval of security alerts.

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
    def _validate_threat_score(threat_score: int) -> None:
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
    def _validate_optional_id(
        value: int | None,
        field_name: str,
    ) -> None:
        """Validate an optional positive database ID."""

        if value is not None and (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value <= 0
        ):
            raise ValueError(
                f"{field_name} must be a positive integer or None."
            )

    def create_alert(
        self,
        alert_type: str,
        severity: str,
        message: str,
        threat_score: int,
        file_path: str | None = None,
        event_id: int | None = None,
        process_id: int | None = None,
        incident_id: int | None = None,
        timestamp: datetime | None = None,
    ) -> Alert:
        """
        Create and stage a security alert.

        The caller is responsible for committing the transaction.
        """

        if not isinstance(alert_type, str) or not alert_type.strip():
            raise ValueError("Alert type cannot be empty.")

        if not isinstance(severity, str) or not severity.strip():
            raise ValueError("Alert severity cannot be empty.")

        if not isinstance(message, str) or not message.strip():
            raise ValueError("Alert message cannot be empty.")

        self._validate_threat_score(threat_score)

        if file_path is not None and (
            not isinstance(file_path, str) or not file_path.strip()
        ):
            raise ValueError(
                "File path must be a non-empty string or None."
            )

        self._validate_optional_id(event_id, "Event ID")
        self._validate_optional_id(process_id, "Process ID")
        self._validate_optional_id(incident_id, "Incident ID")

        if timestamp is None:
            timestamp = datetime.now(timezone.utc)
        elif (
            not isinstance(timestamp, datetime)
            or timestamp.tzinfo is None
            or timestamp.utcoffset() is None
        ):
            raise ValueError("Alert timestamp must be timezone-aware.")

        timestamp = timestamp.astimezone(timezone.utc)

        alert = Alert(
            alert_type=alert_type.strip().upper(),
            severity=severity.strip().upper(),
            message=message.strip(),
            threat_score=threat_score,
            file_path=file_path.strip() if file_path else None,
            event_id=event_id,
            process_id=process_id,
            incident_id=incident_id,
            timestamp=timestamp,
        )

        self.session.add(alert)
        self.session.flush()

        return alert

    def get_alert_by_id(self, alert_id: int) -> Alert | None:
        """Retrieve an alert by its database ID."""

        if (
            isinstance(alert_id, bool)
            or not isinstance(alert_id, int)
            or alert_id <= 0
        ):
            raise ValueError("Alert ID must be a positive integer.")

        statement = select(Alert).where(Alert.id == alert_id)

        return self.session.scalars(statement).first()

    def get_recent_alerts(
        self,
        limit: int = 100,
    ) -> list[Alert]:
        """Retrieve recent alerts, newest first."""

        self._validate_limit(limit)

        statement = (
            select(Alert)
            .order_by(
                Alert.timestamp.desc(),
                Alert.id.desc(),
            )
            .limit(limit)
        )

        return list(self.session.scalars(statement).all())

    def get_alerts_by_severity(
        self,
        severity: str,
        limit: int = 100,
    ) -> list[Alert]:
        """Retrieve alerts filtered by severity, newest first."""

        if not isinstance(severity, str) or not severity.strip():
            raise ValueError("Alert severity cannot be empty.")

        self._validate_limit(limit)

        statement = (
            select(Alert)
            .where(Alert.severity == severity.strip().upper())
            .order_by(
                Alert.timestamp.desc(),
                Alert.id.desc(),
            )
            .limit(limit)
        )

        return list(self.session.scalars(statement).all())

    def get_alerts_by_incident(
        self,
        incident_id: int,
        limit: int = 100,
    ) -> list[Alert]:
        """Retrieve alerts associated with an incident."""

        self._validate_optional_id(incident_id, "Incident ID")

        if incident_id is None:
            raise ValueError("Incident ID cannot be None.")

        self._validate_limit(limit)

        statement = (
            select(Alert)
            .where(Alert.incident_id == incident_id)
            .order_by(
                Alert.timestamp.desc(),
                Alert.id.desc(),
            )
            .limit(limit)
        )

        return list(self.session.scalars(statement).all())
