
import csv
import io
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.database.models import Incident
from app.database.repositories.alert_repository import AlertRepository
from app.database.repositories.event_repository import EventRepository
from app.database.repositories.score_repository import ScoreRepository


def _timestamp(value):
    """Convert a database timestamp into an ISO-8601 UTC string."""
    if value is None:
        return None

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc).isoformat()


def _recommendations(signals):
    """Return recommendations based on recorded detection signals."""
    recommendations = []

    signal_recommendations = {
        "rapid_encryption": (
            "Review rapid file-modification activity and verify whether "
            "the affected files were modified unexpectedly."
        ),
        "mass_rename": (
            "Review the file-renaming activity and verify the affected "
            "file names and extensions."
        ),
        "high_entropy": (
            "Inspect files with unusually high entropy in the isolated "
            "sandbox to determine whether their contents changed."
        ),
        "cpu_spike": (
            "Review the suspect process and its CPU activity around "
            "the incident timestamp."
        ),
        "unknown_program": (
            "Verify the identity, executable path, and legitimacy of "
            "the program associated with the incident."
        ),
    }

    seen = set()

    for signal in signals or []:
        if isinstance(signal, dict):
            signal_name = (
                signal.get("name")
                or signal.get("signal")
                or signal.get("type")
                or ""
            )
        else:
            signal_name = str(signal)

        normalized = signal_name.strip().lower().replace("-", "_").replace(" ", "_")

        if normalized in signal_recommendations and normalized not in seen:
            recommendations.append(signal_recommendations[normalized])
            seen.add(normalized)

    if not recommendations:
        recommendations.append(
            "Review the incident timeline and validate the affected "
            "files and recorded alerts in the isolated sandbox."
        )

    return recommendations


def build_incident_report(session: Session, incident_id: int) -> dict:
    """
    Build a structured incident report using existing database records.

    Filesystem events are associated with an incident only when they
    can be linked through an incident alert or an affected-file path.
    """
    incident = (
        session.query(Incident)
        .filter(Incident.id == incident_id)
        .first()
    )

    if incident is None:
        raise ValueError(f"Incident with ID {incident_id} was not found.")

    alert_repository = AlertRepository(session)
    event_repository = EventRepository(session)
    score_repository = ScoreRepository(session)

    alerts = alert_repository.get_alerts_by_incident(
        incident.id,
        limit=100,
    )

    scores = score_repository.get_scores_by_incident(incident.id)

    # Collect events explicitly linked through incident alerts.
    related_events = {}

    for alert in alerts:
        if alert.event is not None:
            related_events[alert.event.id] = alert.event

    # Collect events matching the incident's recorded affected-file paths.
    affected_files = incident.affected_files or []

    for file_path in affected_files:
        if not isinstance(file_path, str) or not file_path.strip():
            continue

        matching_events = event_repository.get_events_by_path(
            file_path,
            limit=100,
        )

        for event in matching_events:
            related_events[event.id] = event

    # Build a chronological timeline.
    timeline = []

    for event in related_events.values():
        timeline.append({
            "record_type": "filesystem_event",
            "timestamp": _timestamp(event.timestamp),
            "event_id": event.id,
            "event_type": event.event_type,
            "source_path": event.source_path,
            "destination_path": event.destination_path,
            "file_extension": event.file_extension,
            "entropy": event.entropy,
            "association": (
                "Incident alert"
                if any(
                    alert.event_id == event.id
                    for alert in alerts
                )
                else "Affected-file path"
            ),
        })

    for alert in alerts:
        timeline.append({
            "record_type": "alert",
            "timestamp": _timestamp(alert.timestamp),
            "alert_id": alert.id,
            "alert_type": alert.alert_type,
            "severity": alert.severity,
            "message": alert.message,
            "file_path": alert.file_path,
            "threat_score": alert.threat_score,
        })

    timeline.sort(
        key=lambda item: item.get("timestamp") or ""
    )

    # Include the recorded threat-score history.
    score_history = []

    for score in scores:
        score_history.append({
            "score_id": score.id,
            "threat_score": score.threat_score,
            "threat_level": score.threat_level,
            "triggered_signals": score.triggered_signals or [],
            "timestamp": _timestamp(score.timestamp),
        })

    # Include suspect-process information only when linked to the incident.
    suspect_process = None

    if incident.suspect_process is not None:
        process = incident.suspect_process

        suspect_process = {
            "pid": process.pid,
            "name": process.name,
            "executable_path": process.executable_path,
            "parent_pid": process.parent_pid,
            "username": process.username,
            "status": process.status,
            "cpu_percent": process.cpu_percent,
            "memory_percent": process.memory_percent,
            "timestamp": _timestamp(process.timestamp),
        }

    # Use signals recorded against the incident's scores.
    triggered_signals = []

    for score in scores:
        for signal in score.triggered_signals or []:
            if signal not in triggered_signals:
                triggered_signals.append(signal)

    if not triggered_signals:
        for alert in alerts:
            if alert.message:
                # Alert messages are retained as evidence, not interpreted
                # as structured detection signals.
                continue

    recommendations = _recommendations(triggered_signals)

    return {
        "generated_at": _timestamp(datetime.now(timezone.utc)),
        "incident": {
            "id": incident.id,
            "incident_reference": incident.incident_reference,
            "title": incident.title,
            "description": incident.description,
            "severity": incident.severity,
            "status": incident.status,
            "created_at": _timestamp(incident.created_at),
            "updated_at": _timestamp(incident.updated_at),
        },
        "threat_assessment": {
            "threat_score": incident.threat_score,
            "triggered_signals": triggered_signals,
            "score_history": score_history,
        },
        "event_timeline": timeline,
        "affected_files": affected_files,
        "suspect_process": suspect_process,
        "recommendations": recommendations,
    }


def render_incident_report_csv(report: dict) -> str:
    """Render a structured incident report as CSV text."""
    output = io.StringIO()

    fieldnames = [
        "record_type",
        "timestamp",
        "incident_reference",
        "title",
        "severity",
        "status",
        "threat_score",
        "event_type",
        "source_path",
        "destination_path",
        "file_path",
        "entropy",
        "alert_type",
        "message",
        "process_name",
        "process_pid",
        "recommendation",
    ]

    writer = csv.DictWriter(
        output,
        fieldnames=fieldnames,
    )

    writer.writeheader()

    incident = report["incident"]
    threat = report["threat_assessment"]
    process = report["suspect_process"]

    # Incident summary row.
    writer.writerow({
        "record_type": "incident",
        "timestamp": incident["created_at"],
        "incident_reference": incident["incident_reference"],
        "title": incident["title"],
        "severity": incident["severity"],
        "status": incident["status"],
        "threat_score": threat["threat_score"],
        "process_name": process["name"] if process else "Not identified",
        "process_pid": process["pid"] if process else "",
    })

    # Timeline rows.
    for item in report["event_timeline"]:
        writer.writerow({
            "record_type": item["record_type"],
            "timestamp": item.get("timestamp"),
            "incident_reference": incident["incident_reference"],
            "title": incident["title"],
            "severity": incident["severity"],
            "threat_score": item.get("threat_score"),
            "event_type": item.get("event_type"),
            "source_path": item.get("source_path"),
            "destination_path": item.get("destination_path"),
            "file_path": item.get("file_path"),
            "entropy": item.get("entropy"),
            "alert_type": item.get("alert_type"),
            "message": item.get("message"),
        })

    # Affected-file rows.
    for file_path in report["affected_files"]:
        writer.writerow({
            "record_type": "affected_file",
            "incident_reference": incident["incident_reference"],
            "file_path": file_path,
        })

    # Recommendation rows.
    for recommendation in report["recommendations"]:
        writer.writerow({
            "record_type": "recommendation",
            "incident_reference": incident["incident_reference"],
            "recommendation": recommendation,
        })

    return output.getvalue()
