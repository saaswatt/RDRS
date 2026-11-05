
"""
Service responsible for coordinating process collection
and persistence.
"""

from app.collectors.process_monitor import collect_running_processes
from app.database.repositories.process_repository import ProcessRepository
from app.database.session import get_db_session
from app.core.logging import get_logger


system_logger = get_logger("system")
error_logger = get_logger("errors")


def collect_and_store_processes() -> dict[str, int]:
    """
    Collect running processes and persist their snapshots.

    Invalid individual snapshots are skipped.
    Unexpected database errors propagate so the session
    manager can roll back the transaction.
    """

    system_logger.info("Starting process collection cycle.")

    process_snapshots = collect_running_processes()

    collected_count = len(process_snapshots)
    stored_count = 0
    skipped_count = 0

    try:
        with get_db_session() as session:
            repository = ProcessRepository(session)

            for process_info in process_snapshots:
                try:
                    repository.create_process_snapshot(process_info)
                    stored_count += 1

                except (TypeError, ValueError) as exc:
                    skipped_count += 1

                    system_logger.warning(
                        f"Skipping invalid process snapshot: {exc}"
                    )

    except Exception:
        error_logger.exception(
            "Process collection persistence failed."
        )
        raise

    result = {
        "collected": collected_count,
        "stored": stored_count,
        "skipped": skipped_count
    }

    system_logger.info(
        "Process collection cycle completed. "
        f"Collected={collected_count}, "
        f"Stored={stored_count}, "
        f"Skipped={skipped_count}"
    )

    return result
