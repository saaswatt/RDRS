
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from app.core.config import RDRSConfig, load_config
from app.core.logging import get_logger
from app.database.repositories.alert_repository import AlertRepository
from app.database.repositories.incident_repository import IncidentRepository
from app.database.repositories.score_repository import ScoreRepository
from app.database.session import get_db_session
from app.detectors.scoring_engine import calculate_threat_score


system_logger = get_logger("system")
alerts_logger = get_logger("alerts")
audit_logger = get_logger("audit")
error_logger = get_logger("errors")


def process_detection_response(
    detection_results: Mapping[str, Any],
    config: RDRSConfig | None = None,
    timestamp: datetime | None = None,
) -> dict[str, Any]:
    """
    Calculate a threat score and persist the appropriate response.

    NORMAL/WARNING:
        Persist the threat score only.

    CRITICAL:
        Create an incident, persist its linked score,
        and create an aggregate alert.

    All database operations use one transaction.
    No process termination or file modification is performed.
    """

    if not isinstance(detection_results, Mapping):
        raise TypeError("Detection results must be a mapping.")

    signals = detection_results.get("signals")

    if not isinstance(signals, Mapping):
        raise ValueError("Detection results must contain a signals mapping.")

    affected_files = detection_results.get("affected_files", [])

    if not isinstance(affected_files, list):
        raise ValueError("affected_files must be a list.")

    if any(
        not isinstance(path, str) or not path.strip()
        for path in affected_files
    ):
        raise ValueError(
            "Every affected file path must be a non-empty string."
        )

    if config is None:
        config = load_config()

    if not isinstance(config, RDRSConfig):
        raise TypeError("Config must be an RDRSConfig instance.")

    if timestamp is None:
        timestamp = datetime.now(timezone.utc)

    if (
        not isinstance(timestamp, datetime)
        or timestamp.tzinfo is None
        or timestamp.utcoffset() is None
    ):
        raise ValueError("timestamp must be timezone-aware.")

    timestamp = timestamp.astimezone(timezone.utc)

    system_logger.info("Starting incident response processing.")

    try:
        score_result = calculate_threat_score(signals, config)

        threat_score = score_result["threat_score"]
        threat_level = score_result["threat_level"]
        triggered_signals = score_result["triggered_signals"]

        incident_id = None
        incident_reference = None
        alert_id = None

        with get_db_session() as session:
            score_repository = ScoreRepository(session)

            if threat_level == "CRITICAL":
                incident_reference = (
                    f"RDRS-{timestamp.strftime('%Y%m%d%H%M%S')}-"
                    f"{uuid4().hex[:8].upper()}"
                )

                incident_repository = IncidentRepository(session)

                incident = incident_repository.create_incident(
                    incident_reference=incident_reference,
                    title="Critical ransomware-like activity detected",
                    description=(
                        f"RDRS detected critical activity with a threat "
                        f"score of {threat_score}/100. "
                        f"Triggered signals: "
                        f"{', '.join(triggered_signals)}."
                    ),
                    severity=threat_level,
                    threat_score=threat_score,
                    affected_files=affected_files,
                    created_at=timestamp,
                )

                incident_id = incident.id

                score = score_repository.create_score(
                    threat_score=threat_score,
                    threat_level=threat_level,
                    triggered_signals=triggered_signals,
                    timestamp=timestamp,
                    incident_id=incident_id,
                )

                alert_repository = AlertRepository(session)

                alert_message = (
                    f"Critical threat detected. "
                    f"Threat score: {threat_score}/100. "
                    f"Incident: {incident_reference}. "
                    f"Triggered signals: "
                    f"{', '.join(triggered_signals)}."
                )

                alert = alert_repository.create_alert(
                    alert_type="THREAT_DETECTED",
                    severity=threat_level,
                    message=alert_message,
                    threat_score=threat_score,
                    file_path=affected_files[0] if affected_files else None,
                    incident_id=incident_id,
                    timestamp=timestamp,
                )

                alert_id = alert.id

            else:
                score = score_repository.create_score(
                    threat_score=threat_score,
                    threat_level=threat_level,
                    triggered_signals=triggered_signals,
                    timestamp=timestamp,
                )

        # The transaction has committed successfully at this point.
        response = {
            **score_result,
            "score_id": score.id,
            "incident_id": incident_id,
            "incident_reference": incident_reference,
            "alert_id": alert_id,
        }

        system_logger.info(
            f"Threat response completed: "
            f"{threat_level}, score={threat_score}."
        )

        if threat_level == "CRITICAL":
            alerts_logger.warning(
                f"Critical incident created: {incident_reference}, "
                f"score={threat_score}."
            )

            audit_logger.warning(
                f"Incident response recorded: "
                f"incident={incident_reference}, "
                f"score_id={score.id}, alert_id={alert_id}."
            )

            if config.response.terminate_process:
                audit_logger.warning(
                    "Process termination is configured but remains "
                    "simulation-only. No process was terminated."
                )

        else:
            audit_logger.info(
                f"Threat score recorded: score_id={score.id}, "
                f"level={threat_level}, score={threat_score}."
            )

        return response

    except Exception:
        error_logger.exception(
            "Incident response processing failed."
        )
        raise
