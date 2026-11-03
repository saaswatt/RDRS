
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from app.core.config import load_config
from app.core.logging import get_logger


class RDRSEventHandler(FileSystemEventHandler):
    """Handles filesystem events detected by Watchdog."""

    def __init__(self):
        super().__init__()
        self.event_logger = get_logger("events")

    def on_created(self, event):
        if event.is_directory:
            return

        self.event_logger.info(
            f"FILE CREATED | Path: {event.src_path}"
        )

    def on_modified(self, event):
        if event.is_directory:
            return

        self.event_logger.info(
            f"FILE MODIFIED | Path: {event.src_path}"
        )

    def on_deleted(self, event):
        if event.is_directory:
            return

        self.event_logger.warning(
            f"FILE DELETED | Path: {event.src_path}"
        )

    def on_moved(self, event):
        if event.is_directory:
            return

        self.event_logger.warning(
            f"FILE MOVED | Source: {event.src_path} | "
            f"Destination: {event.dest_path}"
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

        print(f"RDRS monitoring started. Watching {scheduled_count} director(y/ies).")
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
    monitor = FilesystemMonitor()
    monitor.run()
