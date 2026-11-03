
from pathlib import Path
from loguru import logger


LOG_DIRECTORY = Path("logs")

LOG_FILES = {
    "system": "system.log",
    "events": "events.log",
    "alerts": "alerts.log",
    "errors": "errors.log",
    "audit": "audit.log",
}


def setup_logging():
    """
    Configure separate logging channels for RDRS.
    """

    # Ensure the log directory exists
    LOG_DIRECTORY.mkdir(parents=True, exist_ok=True)

    # Remove Loguru's default console handler
    logger.remove()

    # Create a dedicated file sink for each channel
    for channel, filename in LOG_FILES.items():

        log_path = LOG_DIRECTORY / filename

        logger.add(
            log_path,
            level="DEBUG",
            filter=lambda record, name=channel: (
                record["extra"].get("channel") == name
            ),
            rotation="5 MB",
            retention="7 days",
            compression="zip",
            encoding="utf-8",
            enqueue=True,
        )


def get_logger(channel: str):
    """
    Return a logger associated with a specific channel.
    """

    if channel not in LOG_FILES:
        raise ValueError(f"Unknown logging channel: {channel}")

    return logger.bind(channel=channel)
