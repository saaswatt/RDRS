import math
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import Event


class EventRepository:
    """
    Repository responsible for database operations
    involving filesystem events.

    The repository receives an existing SQLAlchemy
    session and does not manage its lifecycle.
    """

    def __init__(self, session: Session):
        self.session = session

    @staticmethod
    def _validate_limit(limit: int) -> None:
        """Ensure that the requested result limit is positive."""

        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise ValueError("Limit must be a positive integer.")

    def create_event(
        self,
        event_type: str,
        source_path: str,
        destination_path: str | None = None,
        file_extension: str | None = None,
        timestamp: datetime | None = None,
        is_directory: bool = False,
        entropy: float | None = None
    ) -> Event:
        """
        Create and stage a filesystem event for insertion.
        Entropy is optional because not every filesystem event requires an entropy measurement.
        The caller is responsible for committing the transaction.
        """

        if not isinstance(event_type, str) or not event_type.strip():
            raise ValueError("event_type cannot be empty.")

        if not isinstance(source_path, str) or not source_path.strip():
            raise ValueError("source_path cannot be empty.")

        if destination_path is not None:
            if(
                not isinstance(destination_path, str)
                or not destination_path.strip()
            ): 
                raise ValueError("Destination path cannot be empty.")
        
        if entropy is not None:
            if(
                isinstance(entropy, bool)
                or not isinstance(entropy, (int, float))
                or not math.isfinite(entropy)
                or not 0 <= entropy <= 8
            ):
                raise ValueError("Entropy must be a finite number between 0 and 8.")
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)
        elif(
            timestamp.tzinfo is None
            or timestamp.utcoffset() is None
        ):
            raise ValueError("Timestamp must be timezone-aware.")
        timestamp = timestamp.astimezone(timezone.utc)
        
        event = Event(
            event_type = event_type.strip().upper(),
            source_path = source_path.strip(),
            destination_path = (
                destination_path.strip()
                if destination_path is not None
                else None
            ),
            file_extension=file_extension,
            timestamp=timestamp,
            entropy=float(entropy) if entropy is not None else None,
            is_directory=is_directory
        )
        
        self.session.add(event)
        self.session.flush()
        return event

    def get_event_by_id(self, event_id: int) -> Event | None:
        """
        Retrieve a filesystem event by its unique identifier.

        Returns None if no event is found.
        """

        statement = select(Event).where(Event.id == event_id)

        return self.session.scalars(statement).first()

    def get_recent_events(self, limit: int = 100) -> list[Event]:
        """
        Retrieve the most recent filesystem events.

        Events are ordered from newest to oldest.
        """

        self._validate_limit(limit)

        statement = (
            select(Event)
            .order_by(Event.timestamp.desc(), Event.id.desc())
            .limit(limit)
        )

        return list(self.session.scalars(statement).all())
        
    def get_events_since(self, timestamp: datetime) -> list[Event]:
        """
        Retrieve all filesystem events recorded at or after
        the specified timestamp.

        The input timestamp must be timezone-aware.
        Timestamps are normalized to UTC before querying.

        SQLite does not reliably preserve timezone information
        in DateTime columns, so the UTC cutoff is converted to
        a naive UTC datetime for database comparison.

        Events are returned from oldest to newest.
        """

        if (
            not isinstance(timestamp, datetime)
            or timestamp.tzinfo is None
            or timestamp.utcoffset() is None
        ):
            raise ValueError("Timestamp must be timezone-aware.")

        utc_timestamp = timestamp.astimezone(timezone.utc)

        sqlite_timestamp = utc_timestamp.replace(tzinfo=None)

        statement = (
            select(Event)
            .where(Event.timestamp >= sqlite_timestamp)
            .order_by(Event.timestamp.asc(), Event.id.asc())
        )

        return list(self.session.scalars(statement).all())

    def get_events_by_type(
        self,
        event_type: str,
        limit: int = 100
    ) -> list[Event]:
        """
        Retrieve filesystem events filtered by event type.

        Events are ordered from newest to oldest.
        """

        if not isinstance(event_type, str) or not event_type.strip():
            raise ValueError("Event type cannot be empty.")

        self._validate_limit(limit)

        normalized_event_type = event_type.strip().upper()

        statement = (
            select(Event)
            .where(Event.event_type == normalized_event_type)
            .order_by(Event.timestamp.desc(), Event.id.desc())
            .limit(limit)
        )

        return list(self.session.scalars(statement).all())

    def get_events_by_path(
        self,
        file_path: str,
        limit: int = 100
    ) -> list[Event]:
        """
        Retrieve filesystem events associated with a file path.

        Searches both source_path and destination_path.
        Events are ordered from newest to oldest.
        """

        if not isinstance(file_path, str) or not file_path.strip():
            raise ValueError("File path cannot be empty.")

        self._validate_limit(limit)

        statement = (
            select(Event)
            .where(
                (Event.source_path == file_path)
                | (Event.destination_path == file_path)
            )
            .order_by(Event.timestamp.desc(), Event.id.desc())
            .limit(limit)
        )

        return list(self.session.scalars(statement).all())
