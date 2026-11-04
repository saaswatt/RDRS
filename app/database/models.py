
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


def utc_now() -> datetime:
    """Return the current UTC timestamp."""
    return datetime.now(timezone.utc)


class Event(Base):
    """Stores filesystem activity detected by Watchdog."""

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True
    )

    event_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False
    )

    source_path: Mapped[str] = mapped_column(
        Text,
        nullable=False
    )

    destination_path: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    file_extension: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False
    )

    entropy: Mapped[float | None] = mapped_column(
        Float,
        nullable=True
    )

    is_directory: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False
    )

    alerts: Mapped[list["Alert"]] = relationship(
        back_populates="event"
    )

    __table_args__ = (
        Index("ix_events_timestamp", "timestamp"),
        Index("ix_events_event_type", "event_type"),
    )


class Process(Base):
    """Stores individual process-monitoring snapshots."""

    __tablename__ = "processes"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True
    )

    pid: Mapped[int] = mapped_column(
        Integer,
        nullable=False
    )

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False
    )

    executable_path: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    parent_pid: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True
    )

    process_create_time: Mapped[float | None] = mapped_column(
        Float,
        nullable=True
    )

    cpu_percent: Mapped[float] = mapped_column(
        Float,
        default=0.0,
        nullable=False
    )

    memory_percent: Mapped[float] = mapped_column(
        Float,
        default=0.0,
        nullable=False
    )

    memory_rss: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False
    )

    disk_read_bytes: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True
    )

    disk_write_bytes: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True
    )

    username: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True
    )

    status: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False
    )

    alerts: Mapped[list["Alert"]] = relationship(
        back_populates="process"
    )

    incidents: Mapped[list["Incident"]] = relationship(
        back_populates="suspect_process"
    )

    __table_args__ = (
        Index("ix_processes_pid", "pid"),
        Index("ix_processes_timestamp", "timestamp"),
        Index(
            "ix_processes_pid_create_time",
            "pid",
            "process_create_time"
        ),
        CheckConstraint(
            "cpu_percent >= 0",
            name="ck_process_cpu_nonnegative"
        ),
        CheckConstraint(
            "memory_percent >= 0 AND memory_percent <= 100",
            name="ck_process_memory_percent"
        ),
    )


class Incident(Base):
    """Stores consolidated security incidents."""

    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True
    )

    incident_reference: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False
    )

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False
    )

    description: Mapped[str] = mapped_column(
        Text,
        nullable=False
    )

    severity: Mapped[str] = mapped_column(
        String(32),
        nullable=False
    )

    threat_score: Mapped[int] = mapped_column(
        Integer,
        nullable=False
    )

    status: Mapped[str] = mapped_column(
        String(32),
        default="OPEN",
        nullable=False
    )

    affected_files: Mapped[list[str]] = mapped_column(
        JSON,
        default=list,
        nullable=False
    )

    suspect_process_id: Mapped[int | None] = mapped_column(
        ForeignKey("processes.id"),
        nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False
    )

    suspect_process: Mapped["Process | None"] = relationship(
        back_populates="incidents"
    )

    alerts: Mapped[list["Alert"]] = relationship(
        back_populates="incident"
    )

    scores: Mapped[list["Score"]] = relationship(
        back_populates="incident"
    )

    __table_args__ = (
        Index("ix_incidents_created_at", "created_at"),
        CheckConstraint(
            "threat_score >= 0 AND threat_score <= 100",
            name="ck_incident_threat_score"
        ),
    )


class Score(Base):
    """Stores historical threat-score evaluations."""

    __tablename__ = "scores"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True
    )

    threat_score: Mapped[int] = mapped_column(
        Integer,
        nullable=False
    )

    threat_level: Mapped[str] = mapped_column(
        String(32),
        nullable=False
    )

    triggered_signals: Mapped[list[str]] = mapped_column(
        JSON,
        default=list,
        nullable=False
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False
    )

    incident_id: Mapped[int | None] = mapped_column(
        ForeignKey("incidents.id"),
        nullable=True
    )

    incident: Mapped["Incident | None"] = relationship(
        back_populates="scores"
    )

    __table_args__ = (
        Index("ix_scores_timestamp", "timestamp"),
        CheckConstraint(
            "threat_score >= 0 AND threat_score <= 100",
            name="ck_score_threat_score"
        ),
    )


class Alert(Base):
    """Stores individual security detection alerts."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True
    )

    alert_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False
    )

    severity: Mapped[str] = mapped_column(
        String(32),
        nullable=False
    )

    message: Mapped[str] = mapped_column(
        Text,
        nullable=False
    )

    file_path: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    threat_score: Mapped[int] = mapped_column(
        Integer,
        nullable=False
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False
    )

    event_id: Mapped[int | None] = mapped_column(
        ForeignKey("events.id"),
        nullable=True
    )

    process_id: Mapped[int | None] = mapped_column(
        ForeignKey("processes.id"),
        nullable=True
    )

    incident_id: Mapped[int | None] = mapped_column(
        ForeignKey("incidents.id"),
        nullable=True
    )

    event: Mapped["Event | None"] = relationship(
        back_populates="alerts"
    )

    process: Mapped["Process | None"] = relationship(
        back_populates="alerts"
    )

    incident: Mapped["Incident | None"] = relationship(
        back_populates="alerts"
    )

    __table_args__ = (
        Index("ix_alerts_timestamp", "timestamp"),
        Index("ix_alerts_severity", "severity"),
        CheckConstraint(
            "threat_score >= 0 AND threat_score <= 100",
            name="ck_alert_threat_score"
        ),
    )
