
"""
Repository responsible for database operations
involving process monitoring snapshots.
"""

import math
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import Process


class ProcessRepository:
    """
    Handles persistence and retrieval of process snapshots.

    The repository receives an existing SQLAlchemy
    session and does not manage its lifecycle.
    """

    def __init__(self, session: Session):
        self.session = session

    @staticmethod
    def _validate_optional_number(
        value: Any,
        field_name: str,
        minimum: float = 0.0,
        maximum: float | None = None
    ) -> None:
        """Validate an optional finite numeric value."""

        if value is None:
            return

        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value < minimum
            or (maximum is not None and value > maximum)
        ):
            raise ValueError(
                f"{field_name} must be a finite number "
                f"between {minimum} and {maximum}."
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

    @staticmethod
    def _validate_optional_integer(
        value: Any,
        field_name: str,
        minimum: int = 0
    ) -> None:
        """Validate an optional integer."""

        if value is None:
            return

        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value < minimum
        ):
            raise ValueError(
                f"{field_name} must be an integer "
                f"greater than or equal to {minimum}."
            )

    @staticmethod
    def _validate_optional_string(
        value: Any,
        field_name: str
    ) -> None:
        """Validate an optional string field."""

        if value is not None and not isinstance(value, str):
            raise ValueError(
                f"{field_name} must be a string or None."
            )

    def create_process_snapshot(
        self,
        process_info: dict[str, Any]
    ) -> Process:
        """
        Create and stage a process monitoring snapshot.

        The caller is responsible for committing
        the database transaction.
        """

        if not isinstance(process_info, dict):
            raise TypeError(
                "Process information must be a dictionary."
            )

        # Validate PID.
        pid = process_info.get("pid")

        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            raise ValueError("PID must be a positive integer.")

        # Validate process name.
        name = process_info.get("name")

        if not isinstance(name, str) or not name.strip():
            raise ValueError("Process name must be a non-empty string.")

        # Validate timestamp.
        timestamp = process_info.get("timestamp")

        if not isinstance(timestamp, datetime):
            raise ValueError("A valid timestamp is required.")

        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("Timestamp must be timezone-aware.")

        normalized_timestamp = timestamp.astimezone(timezone.utc)

        # Validate numeric measurements.
        cpu_percent = process_info.get("cpu_percent")
        memory_percent = process_info.get("memory_percent")
        process_create_time = process_info.get("process_create_time")

        self._validate_optional_number(
            cpu_percent,
            "CPU percentage"
        )

        self._validate_optional_number(
            memory_percent,
            "Memory percentage",
            maximum=100.0
        )

        self._validate_optional_number(
            process_create_time,
            "Process creation time"
        )

        # Validate integer measurements and identifiers.
        parent_pid = process_info.get("parent_pid")
        memory_rss = process_info.get("memory_rss")
        disk_read_bytes = process_info.get("disk_read_bytes")
        disk_write_bytes = process_info.get("disk_write_bytes")

        self._validate_optional_integer(
            parent_pid,
            "Parent PID"
        )

        self._validate_optional_integer(
            memory_rss,
            "Memory RSS"
        )

        self._validate_optional_integer(
            disk_read_bytes,
            "Disk read bytes"
        )

        self._validate_optional_integer(
            disk_write_bytes,
            "Disk write bytes"
        )

        # Validate optional text fields.
        executable_path = process_info.get("executable_path")
        username = process_info.get("username")
        status = process_info.get("status")

        self._validate_optional_string(
            executable_path,
            "Executable path"
        )

        self._validate_optional_string(
            username,
            "Username"
        )

        self._validate_optional_string(
            status,
            "Process status"
        )

        # Construct the database model.
        process = Process(
            pid=pid,
            name=name,
            executable_path=executable_path,
            parent_pid=parent_pid,
            process_create_time=process_create_time,
            cpu_percent=cpu_percent,
            memory_percent=memory_percent,
            memory_rss=memory_rss,
            disk_read_bytes=disk_read_bytes,
            disk_write_bytes=disk_write_bytes,
            username=username,
            status=status,
            timestamp=normalized_timestamp
        )

        self.session.add(process)
        self.session.flush()

        return process

    def get_recent_snapshots(
        self,
        limit: int = 100
    ) -> list[Process]:
        """
        Retrieve the most recent process snapshots.

        Results are ordered newest first.
        """

        self._validate_limit(limit)

        statement = (
            select(Process)
            .order_by(
                Process.timestamp.desc(),
                Process.id.desc()
            )
            .limit(limit)
        )

        return list(self.session.scalars(statement).all())

    def get_snapshots_by_pid(
        self,
        pid: int,
        limit: int = 100
    ) -> list[Process]:
        """
        Retrieve snapshots associated with a PID.

        Multiple process instances may share the same PID
        at different points in time.
        """

        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            raise ValueError("PID must be a positive integer.")

        self._validate_limit(limit)

        statement = (
            select(Process)
            .where(Process.pid == pid)
            .order_by(
                Process.timestamp.desc(),
                Process.id.desc()
            )
            .limit(limit)
        )

        return list(self.session.scalars(statement).all())

    def get_snapshots_by_process_instance(
        self,
        pid: int,
        process_create_time: float,
        limit: int = 100
    ) -> list[Process]:
        """
        Retrieve snapshots belonging to one process instance.

        PID and process creation time together distinguish
        process instances when Windows reuses a PID.
        """

        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            raise ValueError("PID must be a positive integer.")

        self._validate_optional_number(
            process_create_time,
            "Process creation time"
        )

        if process_create_time is None:
            raise ValueError("Process creation time is required.")

        self._validate_limit(limit)

        statement = (
            select(Process)
            .where(
                Process.pid == pid,
                Process.process_create_time == process_create_time
            )
            .order_by(
                Process.timestamp.desc(),
                Process.id.desc()
            )
            .limit(limit)
        )

        return list(self.session.scalars(statement).all())
