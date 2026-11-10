
"""
Service responsible for calculating and persisting
threat scores from filesystem detection results.
"""

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from app.core.config import RDRSConfig, load_config
from app.core.logging import get_logger
from app.database.repositories.score_repository import ScoreRepository
from app.database.session import get_db_session
from app.detectors.scoring_engine import calculate_threat_score


system_logger = get_logger("system")
error_logger = get_logger("errors")


def score_detection_results(
    detection_results: Mapping[str, Any],
    config: RDRSConfig | None = None,
    timestamp: datetime | None = None,
) -> dict[str, Any]:
    """
    Calculate a threat score from filesystem detection results
    and persist the score in the database.

    Args:
        detection_results: Output returned by the detection service.
        config: Optional application configuration.
        timestamp: Optional timezone-aware score timestamp.

    Returns:
        Threat score details and the persisted database record ID.
    """

    if not isinstance(detection_results, Mapping):
        raise TypeError("Detection results must be a mapping.")

    signals = detection_results.get("signals")

    if not isinstance(signals, Mapping):
        raise ValueError(
            "Detection results must contain a valid signals mapping."
        )

    if config is None:
        config = load_config()

    system_logger.info(
        "Starting threat score calculation."
    )

    try:
        score_results = calculate_threat_score(
            signals=signals,
            config=config,
        )

        with get_db_session() as session:
            repository = ScoreRepository(session)

            score_record = repository.create_score(
                threat_score=score_results["threat_score"],
                threat_level=score_results["threat_level"],
                triggered_signals=score_results["triggered_signals"],
                timestamp=timestamp,
            )

            score_results["score_id"] = score_record.id

    except Exception:
        error_logger.exception(
            "Threat score calculation or persistence failed."
        )
        raise

    system_logger.info(
        "Threat score calculation completed. "
        f"Score={score_results['threat_score']}, "
        f"Level={score_results['threat_level']}, "
        f"Record ID={score_results['score_id']}"
    )

    return score_results
