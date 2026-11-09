from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from app.core.config import load_config
from app.core.entropy import calculate_file_entropy
from app.core.logging import setup_logging, get_logger
from app.database.repositories.event_repository import EventRepository
from app.database.session import get_db_session


class RDRSEventHandler(FileSystemEventHandler):
    """Handles and persists filesystem events detected by Watchdog."""

    def __init__(self):
        super().__init__()

        self.event_logger = get_logger("events")
        self.error_logger = get_logger("errors")

    def _calculate_entropy_safely(self, file_path: str) -> float | None:
        """
        Calculate file entropy without allowing file-access
        failures to interrupt filesystem event processing.
        """

        try:
            return calculate_file_entropy(file_path)

        except (OSError, ValueError) as exc:
            self.event_logger.warning(
                f"Entropy calculation unavailable | "
                f"Path: {file_path} | Reason: {exc}"
            )

            return None

        except Exception:
            self.error_logger.exception(
                f"Unexpected entropy calculation failure | "
                f"Path: {file_path}"
            )

            return None

    def _process_file_event(
        self,
        event_type: str,
        source_path: str,
        destination_path: str | None = None,
        calculate_entropy: bool = False
    ) -> None:
        """
        Calculate optional entropy and persist one filesystem event.

        Every event uses an independent database session.
        Persistence failures are isolated from the Watchdog thread.
        """

        entropy = None

        if calculate_entropy:
            entropy = self._calculate_entropy_safely(source_path)

        file_extension = Path(source_path).suffix or None

        try:
            with get_db_session() as session:
                repository = EventRepository(session)

                repository.create_event(
                    event_type=event_type,
                    source_path=source_path,
                    destination_path=destination_path,
                    file_extension=file_extension,
                    entropy=entropy,
                    is_directory=False
                )

            self.event_logger.info(
                f"FILE EVENT RECORDED | "
                f"Type: {event_type} | "
                f"Source: {source_path} | "
                f"Destination: {destination_path} | "
                f"Entropy: {entropy}"
            )

        except Exception:
            self.error_logger.exception(
                f"Failed to persist filesystem event | "
                f"Type: {event_type} | "
                f"Source: {source_path} | "
                f"Destination: {destination_path}"
            )

    def on_created(self, event):
        """Handle file creation events."""

        if event.is_directory:
            return

        self._process_file_event(
            event_type="CREATED",
            source_path=event.src_path,
            calculate_entropy=True
        )

    def on_modified(self, event):
        """Handle file modification events."""

        if event.is_directory:
            return

        self._process_file_event(
            event_type="MODIFIED",
            source_path=event.src_path,
            calculate_entropy=True
        )

    def on_deleted(self, event):
        """Handle file deletion events."""

        if event.is_directory:
            return

        self._process_file_event(
            event_type="DELETED",
            source_path=event.src_path
        )

    def on_moved(self, event):
        """Handle file movement and rename events."""

        if event.is_directory:
            return

        self._process_file_event(
            event_type="MOVED",
            source_path=event.src_path,
            destination_path=event.dest_path
        )


class FilesystemMonitor:
    """Monitors configured directories using Watchdog."""

    def __init__(self):
        self.config = load_config()
        self.observer = Observer()
        self.event_handler = RDRSEventHandler()
        self.system_logger = get_logger("system")

    def start(self):
        """Register directories and start filesystem monitoring."""

        directories = self.config.monitoring.directories

        if not directories:
            raise ValueError("No monitoring directories configured.")

        scheduled_count = 0

        for directory in directories:
            path = Path(directory).resolve()

            if not path.exists():
                raise FileNotFoundError(
                    f"Monitoring directory does not exist: {path}"
                )

            if not path.is_dir():
                raise NotADirectoryError(
                    f"Monitoring path is not a directory: {path}"
                )

            self.observer.schedule(
                self.event_handler,
                str(path),
                recursive=self.config.monitoring.recursive
            )

            scheduled_count += 1

            self.system_logger.info(
                f"Monitoring scheduled: {path}"
            )

        self.observer.start()

        self.system_logger.info(
            f"RDRS filesystem monitoring started. "
            f"Directories monitored: {scheduled_count}"
        )

        print(
            f"RDRS monitoring started. "
            f"Watching {scheduled_count} director(y/ies)."
        )
        print("Press Ctrl+C to stop monitoring.")

    def stop(self):
        """Stop the observer gracefully."""

        if self.observer.is_alive():
            self.observer.stop()
            self.observer.join()

        self.system_logger.info(
            "RDRS filesystem monitoring stopped."
        )

        print("RDRS monitoring stopped.")

    def run(self):
        """Keep the monitoring process alive."""

        try:
            self.start()

            while self.observer.is_alive():
                self.observer.join(timeout=1)

        except KeyboardInterrupt:
            print("\nShutdown requested.")

        finally:
            self.stop()


if __name__ == "__main__":
    setup_logging()

    monitor = FilesystemMonitor()
    monitor.run()