
from fastapi.testclient import TestClient

from app.api import main as api_module


client = TestClient(api_module.app)


def test_scan_triggers_detection_cycle(monkeypatch):
    class FakeCoordinator:
        def __init__(self, config):
            self.config = config

        def run_cycle(self):
            return {
                "threat_score": 0,
                "threat_level": "NORMAL",
                "signals": {},
            }

    monkeypatch.setattr(
        api_module,
        "load_config",
        lambda path: object(),
    )
    monkeypatch.setattr(
        api_module,
        "DetectionCoordinator",
        FakeCoordinator,
    )

    response = client.post("/scan")

    assert response.status_code == 200
    assert response.json() == {
        "status": "completed",
        "result": {
            "threat_score": 0,
            "threat_level": "NORMAL",
            "signals": {},
        },
    }


def test_settings_updates_configuration_file(tmp_path, monkeypatch):
    config_path = tmp_path / "config.yaml"
    monkeypatch.setattr(api_module, "CONFIG_PATH", config_path)

    payload = {
        "application": {
            "name": "RDRS",
            "version": "1.0.0",
            "simulation_mode": True,
        },
        "monitoring": {
            "directories": ["./data/sandbox"],
            "recursive": True,
        },
        "detection": {
            "window_seconds": 60,
            "thresholds": {
                "rapid_modification": 30,
                "mass_rename": 15,
                "high_entropy": 7.0,
                "cpu_spike": 80,
            },
        },
        "scoring": {
            "rapid_encryption": 40,
            "mass_rename": 30,
            "high_entropy": 25,
            "cpu_spike": 15,
            "unknown_program": 10,
        },
        "response": {
            "simulation_mode": True,
            "copy_evidence": True,
            "terminate_process": False,
        },
        "database": {
            "path": "./data/rdrs.db",
        },
        "quarantine": {
            "path": "./data/quarantine",
        },
    }

    response = client.post("/settings", json=payload)

    assert response.status_code == 200
    assert response.json()["status"] == "success"
    assert config_path.exists()

    import yaml

    with config_path.open("r", encoding="utf-8") as file:
        saved_config = yaml.safe_load(file)

    assert saved_config == payload


def test_settings_rejects_invalid_configuration(tmp_path, monkeypatch):
    config_path = tmp_path / "config.yaml"
    monkeypatch.setattr(api_module, "CONFIG_PATH", config_path)

    invalid_payload = {
        "application": {
            "name": "RDRS",
            "version": "1.0.0",
            "simulation_mode": True,
        },
        "monitoring": {
            "directories": ["./data/sandbox"],
            "recursive": True,
        },
        "detection": {
            "window_seconds": 60,
            "thresholds": {
                "rapid_modification": 30,
                "mass_rename": 15,
                "high_entropy": 9.5,
                "cpu_spike": 80,
            },
        },
        "scoring": {
            "rapid_encryption": 40,
            "mass_rename": 30,
            "high_entropy": 25,
            "cpu_spike": 15,
            "unknown_program": 10,
        },
        "response": {
            "simulation_mode": True,
            "copy_evidence": True,
            "terminate_process": False,
        },
        "database": {
            "path": "./data/rdrs.db",
        },
        "quarantine": {
            "path": "./data/quarantine",
        },
    }

    response = client.post("/settings", json=invalid_payload)

    assert response.status_code == 422
    assert not config_path.exists()
def test_get_processes_returns_recent_snapshots(monkeypatch):
    from datetime import datetime, timezone
    from types import SimpleNamespace

    timestamp = datetime.now(timezone.utc)

    fake_process = SimpleNamespace(
        id=1,
        pid=1234,
        name="example.exe",
        executable_path="C:\\Windows\\System32\\example.exe",
        parent_pid=1000,
        process_create_time=timestamp.timestamp(),
        cpu_percent=12.5,
        memory_percent=4.5,
        memory_rss=102400,
        disk_read_bytes=2048,
        disk_write_bytes=4096,
        username="SYSTEM",
        status="running",
        timestamp=timestamp,
    )

    class FakeProcessRepository:
        def __init__(self, session):
            self.session = session

        def get_recent_snapshots(self, limit=100):
            assert limit == 100
            return [fake_process]

    class FakeSessionContext:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc_value, traceback):
            return False

    monkeypatch.setattr(
        api_module,
        "ProcessRepository",
        FakeProcessRepository,
    )

    monkeypatch.setattr(
        api_module,
        "get_db_session",
        lambda: FakeSessionContext(),
    )

    response = client.get("/processes")

    assert response.status_code == 200

    data = response.json()

    assert len(data) == 1
    assert data[0]["id"] == 1
    assert data[0]["pid"] == 1234
    assert data[0]["name"] == "example.exe"
    assert data[0]["cpu_percent"] == 12.5
    assert data[0]["memory_percent"] == 4.5
    assert data[0]["disk_read_bytes"] == 2048
    assert data[0]["disk_write_bytes"] == 4096
    assert data[0]["timestamp"] == timestamp.isoformat()