
import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from app.core.config import RDRSConfig
from app.core.logging import get_logger
from app.services.detection_service import run_filesystem_detection
from app.services.incident_response_service import (
    process_detection_response,
)


system_logger = get_logger("system")
error_logger = get_logger("errors")


class DetectionCoordinator:
    """Coordinate detection cycles and prevent duplicate responses."""

    def __init__(self, config: RDRSConfig):
        self.config = config
        self.last_successful_fingerprint: str | None = None

    @staticmethod
    def _create_fingerprint(
        detection_results: dict[str, Any],
    ) -> str:
        """Create a stable fingerprint for a detection result."""

        fingerprint_data = {
            "event_ids": sorted(
                detection_results.get("event_ids", [])
            ),
            "signals": detection_results.get("signals", {}),
        }

        serialized = json.dumps(
            fingerprint_data,
            sort_keys=True,
            separators=(",", ":"),
        )

        return hashlib.sha256(
            serialized.encode("utf-8")
        ).hexdigest()

    def run_cycle(
        self,
        current_time: datetime | None = None,
    ) -> dict[str, Any] | None:
        """
        Run detection and submit new detection results
        to the incident response service.
        """

        if current_time is None:
            current_time = datetime.now(timezone.utc)

        if (
            not isinstance(current_time, datetime)
            or current_time.tzinfo is None
            or current_time.utcoffset() is None
        ):
            raise ValueError(
                "current_time must be timezone-aware."
            )

        system_logger.info("Detection coordinator cycle started.")

        try:
            detection_results = run_filesystem_detection(
                config=self.config,
                current_time=current_time,
            )

            fingerprint = self._create_fingerprint(
                detection_results
            )

            if fingerprint == self.last_successful_fingerprint:
                system_logger.info(
                    "Detection response skipped: "
                    "no new detection information."
                )

                return None

            response = process_detection_response(
                detection_results=detection_results,
                config=self.config,
                timestamp=current_time,
            )

            # Update only after the response service succeeds.
            self.last_successful_fingerprint = fingerprint

            system_logger.info(
                "Detection coordinator cycle completed. "
                f"Threat level={response['threat_level']}, "
                f"Score={response['threat_score']}."
            )

            return response

        except Exception:
            error_logger.exception(
                "Detection coordinator cycle failed."
            )
            raise
