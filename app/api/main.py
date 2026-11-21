
from pathlib import Path

import yaml
from fastapi import FastAPI, HTTPException
from fastapi.encoders import jsonable_encoder
from fastapi.responses import Response
from sqlalchemy import func, select
from fastapi.staticfiles import StaticFiles

from app.core.config import RDRSConfig, load_config
from app.database.models import Alert, Event, Incident, Process, Score
from app.database.session import get_db_session
from app.database.repositories.process_repository import ProcessRepository
from app.services.detection_coordinator import DetectionCoordinator
from app.services.report_service import (
    build_incident_report,
    render_incident_report_csv,
)


CONFIG_PATH = Path("config.yaml")


app = FastAPI(
    title="RDRS API",
    description="Ransomware Detection and Response System REST API",
    version="1.0.0",
)

DASHBOARD_PATH = Path(__file__).resolve().parents[1] / "dashboard"

app.mount(
    "/dashboard",
    StaticFiles(directory=DASHBOARD_PATH, html=True),
    name="dashboard",
)


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "application": "RDRS",
    }


@app.get("/status")
def status():
    with get_db_session() as session:
        latest_score = session.scalar(
            select(Score).order_by(Score.timestamp.desc(), Score.id.desc())
        )

        return {
            "application": "RDRS",
            "threat_score": (
                latest_score.threat_score if latest_score else 0
            ),
            "threat_level": (
                latest_score.threat_level if latest_score else "NORMAL"
            ),
            "total_events": session.scalar(
                select(func.count()).select_from(Event)
            ),
            "total_processes": session.scalar(
                select(func.count()).select_from(Process)
            ),
            "total_alerts": session.scalar(
                select(func.count()).select_from(Alert)
            ),
            "total_incidents": session.scalar(
                select(func.count()).select_from(Incident)
            ),
        }


@app.get("/processes")
def get_processes():
    with get_db_session() as session:
        repository = ProcessRepository(session)
        processes = repository.get_recent_snapshots(limit=100)

        return [
            {
                "id": process.id,
                "pid": process.pid,
                "name": process.name,
                "executable_path": process.executable_path,
                "parent_pid": process.parent_pid,
                "process_create_time": process.process_create_time,
                "cpu_percent": process.cpu_percent,
                "memory_percent": process.memory_percent,
                "memory_rss": process.memory_rss,
                "disk_read_bytes": process.disk_read_bytes,
                "disk_write_bytes": process.disk_write_bytes,
                "username": process.username,
                "status": process.status,
                "timestamp": process.timestamp.isoformat(),
            }
            for process in processes
        ]


@app.get("/alerts")
def get_alerts():
    with get_db_session() as session:
        alerts = session.scalars(
            select(Alert).order_by(
                Alert.timestamp.desc(),
                Alert.id.desc()
            ).limit(100)
        ).all()

        return [
            {
                "id": alert.id,
                "alert_type": alert.alert_type,
                "severity": alert.severity,
                "message": alert.message,
                "file_path": alert.file_path,
                "threat_score": alert.threat_score,
                "timestamp": alert.timestamp.isoformat(),
            }
            for alert in alerts
        ]


@app.get("/events")
def get_events():
    with get_db_session() as session:
        events = session.scalars(
            select(Event).order_by(
                Event.timestamp.desc(),
                Event.id.desc()
            ).limit(100)
        ).all()

        return [
            {
                "id": event.id,
                "event_type": event.event_type,
                "source_path": event.source_path,
                "destination_path": event.destination_path,
                "file_extension": event.file_extension,
                "entropy": event.entropy,
                "is_directory": event.is_directory,
                "timestamp": event.timestamp.isoformat(),
            }
            for event in events
        ]


@app.get("/reports")
def get_reports():
    with get_db_session() as session:
        incidents = session.scalars(
            select(Incident).order_by(
                Incident.created_at.desc(),
                Incident.id.desc()
            ).limit(100)
        ).all()

        return [
            {
                "id": incident.id,
                "incident_reference": incident.incident_reference,
                "title": incident.title,
                "severity": incident.severity,
                "threat_score": incident.threat_score,
                "status": incident.status,
                "affected_files": incident.affected_files,
                "created_at": incident.created_at.isoformat(),
            }
            for incident in incidents
        ]


@app.get("/reports/{incident_id}/json")
def download_json_report(incident_id: int):
    with get_db_session() as session:
        try:
            report = build_incident_report(session, incident_id)
        except ValueError as exc:
            raise HTTPException(
                status_code=404,
                detail=str(exc),
            ) from exc

        return jsonable_encoder(report)


@app.get("/reports/{incident_id}/csv")
def download_csv_report(incident_id: int):
    with get_db_session() as session:
        try:
            report = build_incident_report(session, incident_id)
        except ValueError as exc:
            raise HTTPException(
                status_code=404,
                detail=str(exc),
            ) from exc

        csv_content = render_incident_report_csv(report)

        incident_reference = report["incident"]["incident_reference"]
        filename = f"{incident_reference}_report.csv"

        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={
                "Content-Disposition": (
                    f'attachment; filename="{filename}"'
                )
            },
        )


@app.post("/scan")
def scan():
    config = load_config(str(CONFIG_PATH))
    coordinator = DetectionCoordinator(config)

    result = coordinator.run_cycle()

    return {
        "status": "completed",
        "result": jsonable_encoder(result),
    }


@app.post("/settings")
def update_settings(config: RDRSConfig):
    validated_config = config.model_dump(mode="json")

    with CONFIG_PATH.open("w", encoding="utf-8") as file:
        yaml.safe_dump(
            validated_config,
            file,
            sort_keys=False,
            allow_unicode=True,
        )

    return {
        "status": "success",
        "message": "Configuration updated successfully.",
        "configuration": validated_config,
    }
