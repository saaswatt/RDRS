# RDRS – Ransomware Detection and Response System

RDRS is a defensive cybersecurity application designed to monitor filesystem activity, identify ransomware-like behaviour, calculate threat scores, and generate security alerts and incident reports.

The project combines filesystem monitoring, process metadata collection, entropy analysis, rule-based detection, weighted threat scoring, incident management, and a REST API with a live monitoring dashboard.

**Project type:** Defensive cybersecurity  
**Primary platform:** Windows  
**Language:** Python 3.12+  
**Database:** SQLite  
**Execution mode:** Simulation mode

---

## 1. Objectives

- Monitor configured directories for filesystem activity.
- Calculate file entropy using Shannon entropy.
- Collect process metadata using psutil.
- Detect suspicious filesystem activity.
- Calculate weighted threat scores.
- Generate security alerts and incident records.
- Maintain event, process, alert, and incident records.
- Provide a REST API using FastAPI.
- Display monitoring information through a web dashboard.
- Generate incident reports in JSON and CSV formats.

---

## 2. Technology Stack

| Component | Technology |
|---|---|
| Programming language | Python 3.12+ |
| Filesystem monitoring | Watchdog |
| Process monitoring | psutil |
| Data validation | Pydantic |
| Configuration | PyYAML |
| Logging | Loguru |
| Database ORM | SQLAlchemy |
| Database | SQLite |
| Backend API | FastAPI |
| ASGI server | Uvicorn |
| Frontend | HTML, CSS, Bootstrap, JavaScript |
| Testing | pytest, pytest-cov |

---

## 3. Architecture Overview

RDRS is organized into the following major components:

- **Core:** Application configuration, logging, and shared functionality.
- **Collectors:** Collects process metadata.
- **Detectors:** Monitors filesystem activity and identifies suspicious behaviour.
- **Services:** Coordinates detection, threat scoring, incident response, and reporting.
- **Database:** Stores events, processes, alerts, incidents, and threat scores.
- **API:** Exposes application functionality through REST endpoints.
- **Dashboard:** Displays system status, alerts, filesystem events, and monitoring charts.
- **Tests:** Contains automated tests for application components.

### Detection workflow

1. Filesystem activity is monitored.
2. Process metadata is collected periodically.
3. Detection components analyse available activity.
4. Threat signals are evaluated by the scoring engine.
5. A threat score and threat level are calculated.
6. Critical activity can produce an incident and security alert.
7. Incident information can be retrieved through JSON and CSV reports.

---

## 4. Installation

### Prerequisites

- Windows 10 or Windows 11.
- Python 3.12 or later.
- Git.
- PowerShell.

### Clone the repository

```powershell
git clone <repository-url>
cd RDRS
```


### Create a virtual environment

```powershell
python -m venv .venv
```

### Activate the environment

```powershell
.\.venv\Scripts\Activate.ps1
```

### Install dependencies

```powershell
python -m pip install -r requirements.txt
```

---

## 5. Configuration

Application settings are maintained in `config.yaml`.

Important configuration sections include:

- `application`: Application name, version, and simulation mode.
- `monitoring`: Directories monitored by RDRS and recursive monitoring settings.
- `detection`: Detection interval and thresholds.
- `scoring`: Weights assigned to detection signals.
- `response`: Simulation mode and response-related settings.
- `database`: SQLite database location.
- `quarantine`: Configured quarantine directory.

### Safety configuration

RDRS should be operated in simulation mode.

The recommended safety settings are:

```yaml
application:
  simulation_mode: true

response:
  simulation_mode: true
  copy_evidence: true
  terminate_process: false
```

**Important:** Evidence copying and quarantine handling are configured but are not implemented in the current version. Process termination is not performed by the current incident-response implementation.

---

## 6. Running the Application

RDRS uses separate processes for its monitoring engine and API server.

### Terminal 1: Start the monitoring engine

Activate the virtual environment and run:

```powershell
python -m app.main
```

The monitoring engine initializes the database, starts filesystem monitoring, collects process metadata, and periodically executes detection cycles.

Press `Ctrl+C` to stop the application.

### Terminal 2: Start the API server

Activate the virtual environment in another PowerShell terminal and run:

```powershell
uvicorn app.api.main:app --reload
```

The API server runs locally at:

```text
http://127.0.0.1:8000
```

The `--reload` option is intended for development.

---

## 7. Dashboard and API Access

### Web dashboard

Open:

```text
http://127.0.0.1:8000/dashboard/
```

### Interactive API documentation

Open:

```text
http://127.0.0.1:8000/docs
```

### Available API endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | Application health |
| GET | `/status` | Overall system status |
| GET | `/processes` | Recent process snapshots |
| GET | `/alerts` | Security alerts |
| GET | `/events` | Filesystem events |
| GET | `/reports` | Incident records |
| GET | `/reports/{incident_id}/json` | Generate JSON incident report |
| GET | `/reports/{incident_id}/csv` | Generate CSV incident report |
| POST | `/scan` | Execute a detection cycle |
| POST | `/settings` | Update application configuration |

---

## 8. Incident Reporting

RDRS supports incident report generation in two formats:

- **JSON:** Structured incident information, including the incident summary, threat score, timeline, affected files, available suspect-process information, and recommendations.
- **CSV:** Tabular incident information suitable for spreadsheet applications and further analysis.

Example endpoints:

```text
GET /reports/1/json
GET /reports/1/csv
```

---

## 9. Testing

The project uses pytest for automated testing and pytest-cov for coverage measurement.

Run the test suite:

```powershell
pytest -v
```

Run tests with coverage:

```powershell
pytest --cov=app --cov-report=term-missing
```

### Latest recorded test results

| Metric | Result |
|---|---:|
| Tests collected | 244 |
| Tests passed | 244 |
| Tests failed | 0 |
| Total coverage | 79% |

Coverage represents the recorded test run and may change as the project evolves.

---

## 10. Safe Testing Guidelines

RDRS is intended for defensive security monitoring and controlled simulation.

- Keep simulation mode enabled.
- Use only disposable files inside an isolated sandbox.
- Do not test against real user data or another person's computer.
- Do not execute actual ransomware or malware.
- Do not enable process termination.
- Preserve original files and maintain backups.

The project has been tested using simulated filesystem activity involving disposable files in the configured sandbox.

---

## 11. Current Limitations

The current implementation has the following limitations:

- Automated evidence copying is not implemented.
- Quarantine handling is not implemented.
- Suspect-process attribution is not consistently available for incidents.
- PDF incident report generation is not exposed through the current API.
- Docker deployment has not yet been implemented.
- Test coverage is currently below the 90% target described in the development guide.

These are areas for future development.

---

## 12. Future Improvements

Potential future work includes:

- Implementing safe evidence preservation.
- Improving process-to-incident attribution.
- Expanding automated test coverage.
- Adding PDF incident report generation.
- Containerizing the application using Docker.
- Improving detection accuracy and reducing false positives.

---
