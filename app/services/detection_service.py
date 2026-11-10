
"""
Service responsible for retrieving filesystem events
and coordinating sliding-window detection.
"""

from datetime import datetime, timedelta, timezone
from typing import Any

from app.core.config import RDRSConfig, load_config
from app.core.logging import get_logger
from app.database.repositories.event_repository import EventRepository
from app.database.session import get_db_session
from app.detectors.detection_engine import analyze_filesystem_events


system_logger = get_logger("system")
error_logger = get_logger("errors")


def run_filesystem_detection(
    config: RDRSConfig | None = None,
    current_time: datetime | None = None,
) -> dict[str, Any]:
    """
    Retrieve filesystem events from the configured sliding window
    and analyse them using the filesystem detection engine.

    Returns:
        Detection results, sliding-window boundaries,
        affected file paths, and database event IDs.
    """

    if config is None:
        config = load_config()

    if current_time is None:
        current_time = datetime.now(timezone.utc)

    if (
        not isinstance(current_time, datetime)
        or current_time.tzinfo is None
        or current_time.utcoffset() is None
    ):
        raise ValueError("current_time must be timezone-aware.")

    window_end = current_time.astimezone(timezone.utc)

    window_start = window_end - timedelta(
        seconds=config.detection.window_seconds
    )

    system_logger.info(
        "Starting filesystem detection cycle. "
        f"Window={config.detection.window_seconds}s, "
        f"Start={window_start.isoformat()}, "
        f"End={window_end.isoformat()}"
    )

    try:
        with get_db_session() as session:
            repository = EventRepository(session)

            database_events = repository.get_events_since(window_start)
            window_events = []

            for event in database_events:
                event_timestamp = event.timestamp

                if event_timestamp.tzinfo is None:
                    event_timestamp = event_timestamp.replace(
                        tzinfo=timezone.utc
                    )
                else:
                    event_timestamp = event_timestamp.astimezone(
                        timezone.utc
                    )

                if window_start <= event_timestamp <= window_end:
                    window_events.append(event)

            relevant_events = [
                event
                for event in window_events
                if not event.is_directory
            ]

            filesystem_events = [
                {
                    "event_type": event.event_type,
                    "source_path": event.source_path,
                    "destination_path": event.destination_path,
                    "file_extension": event.file_extension,
                    "entropy": event.entropy,
                    "is_directory": event.is_directory,
                }
                for event in relevant_events
            ]

            results = analyze_filesystem_events(
                filesystem_events,
                config,
            )

            affected_files = []
            seen_paths = set()

            for event in relevant_events:
                paths = [
                    event.source_path,
                    event.destination_path,
                ]

                for path in paths:
                    if path and path not in seen_paths:
                        affected_files.append(path)
                        seen_paths.add(path)

            event_ids = [
                event.id
                for event in relevant_events
            ]

    except Exception:
        error_logger.exception(
            "Filesystem detection cycle failed."
        )
        raise

    results["window_start"] = window_start.isoformat()
    results["window_end"] = window_end.isoformat()
    results["affected_files"] = affected_files
    results["event_ids"] = event_ids

    system_logger.info(
        "Filesystem detection cycle completed. "
        f"Events={results['event_count']}, "
        f"Affected files={len(affected_files)}, "
        f"Signals={results['signals']}"
    )

    return results
