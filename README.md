
# RDRS – Ransomware Detection and Response System

RDRS is a defensive cybersecurity application designed to
monitor filesystem activity, identify ransomware-like behaviour,
and generate security alerts.

## Objectives

- Monitor configured directories in real time.
- Calculate file entropy using Shannon entropy.
- Collect process metadata using psutil.
- Detect suspicious filesystem activity.
- Calculate weighted threat scores.
- Generate alerts and incident records.
- Preserve evidence in a quarantine directory.
- Provide a REST API and monitoring dashboard.
- Generate incident reports.

## Technology Stack

- Python 3.12+
- Watchdog
- psutil
- Pydantic
- PyYAML
- Loguru
- SQLAlchemy
- SQLite
- FastAPI
- HTML, Bootstrap and JavaScript
- pytest

## Project Status

Day 1 – Initial setup and configuration management.

## Safety

RDRS is intended for defensive security monitoring.
Simulation mode is enabled by default.
Testing must be performed using disposable files in an
isolated sandbox.

## Installation

Clone the repository and create a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Configuration

Application settings are maintained in `config.yaml`.

## License

To be determined.
