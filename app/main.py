
import signal
import threading
import time

from app.core.config import load_config
from app.core.logging import setup_logging, get_logger
from app.database.connection import initialize_database
from app.database.session import engine
from app.detectors.filesystem_monitor import FilesystemMonitor
from app.services.detection_coordinator import DetectionCoordinator
from app.services.process_service import collect_and_store_processes


system_logger = get_logger("system")
error_logger = get_logger("errors")


def main():
    setup_logging()

    system_logger.info("Starting RDRS application.")

    monitor = None
    shutdown_event = threading.Event()

    try:
        # Load application configuration.
        config = load_config()

        # Initialize the existing database.
        initialize_database(engine)
        system_logger.info("Database initialized successfully.")

        # Create the detection coordinator.
        coordinator = DetectionCoordinator(config)

        # Start filesystem monitoring.
        monitor = FilesystemMonitor()
        monitor.start()

        system_logger.info("Filesystem monitoring started.")

        system_logger.info(
            "RDRS application is running. Press Ctrl+C to stop."
        )

        # Run detection and process collection periodically.
        while not shutdown_event.is_set():

            try:
                collect_and_store_processes()
            except Exception:
                error_logger.exception(
                    "Process collection cycle failed. "
                    "Application will continue."
                )

            try:
                coordinator.run_cycle()
            except Exception:
                error_logger.exception(
                    "Detection cycle failed. Application will continue."
                )

            shutdown_event.wait(config.detection.window_seconds)

    except KeyboardInterrupt:
        system_logger.info("Shutdown signal received.")

    except Exception:
        error_logger.exception("RDRS application startup failed.")
        raise

    finally:
        shutdown_event.set()

        if monitor is not None:
            monitor.stop()
            system_logger.info("Filesystem monitoring stopped.")

        system_logger.info("RDRS application stopped.")


if __name__ == "__main__":
    main()
