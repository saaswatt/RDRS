
from pathlib import Path
from typing import Any

from app.core.config import RDRSConfig


def analyze_filesystem_events(
    events: list[dict[str, Any]],
    config: RDRSConfig,
) -> dict[str, Any]:
    """
    Analyse filesystem events and identify ransomware-related indicators.

    The caller is responsible for supplying events already filtered
    to the configured detection time window.
    """

    modified_count = 0
    rename_count = 0
    extension_change_count = 0

    entropy_values: list[float] = []

    for event in events:
        event_type = str(event.get("event_type", "")).upper()

        if event_type == "MODIFIED":
            modified_count += 1

        elif event_type == "MOVED":
            rename_count += 1

            source_path = event.get("source_path")
            destination_path = event.get("destination_path")

            if source_path and destination_path:
                source_extension = Path(source_path).suffix.lower()
                destination_extension = Path(destination_path).suffix.lower()

                if source_extension != destination_extension:
                    extension_change_count += 1

        if event_type in {"CREATED", "MODIFIED"}:
            entropy = event.get("entropy")

            if (
                isinstance(entropy, (int, float))
                and not isinstance(entropy, bool)
            ):
                entropy_values.append(float(entropy))

    average_entropy = (
        sum(entropy_values) / len(entropy_values)
        if entropy_values
        else None
    )

    thresholds = config.detection.thresholds

    signals = {
        "rapid_modification": (
            modified_count >= thresholds.rapid_modification
        ),
        "mass_rename": (
            rename_count >= thresholds.mass_rename
        ),
        "high_entropy": (
            average_entropy is not None
            and average_entropy >= thresholds.high_entropy
        ),
    }

    return {
        "window_seconds": config.detection.window_seconds,
        "event_count": len(events),
        "modified_count": modified_count,
        "rename_count": rename_count,
        "extension_change_count": extension_change_count,
        "average_entropy": average_entropy,
        "signals": signals,
    }
