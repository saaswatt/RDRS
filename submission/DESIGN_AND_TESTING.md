# RDRS – Design and Testing Summary

## 1. Project Overview

Ransomware Detection and Response System (RDRS) is a defensive cybersecurity application developed to monitor filesystem activity, identify ransomware-like behaviour, calculate threat scores, and generate security alerts and incident reports.

The application uses Python 3.12+, FastAPI, SQLite, Watchdog and psutil.

## 2. Design and Architecture

RDRS follows a modular architecture:

- Filesystem monitoring: Watchdog monitors configured directories and records filesystem activity.
- Process monitoring: psutil collects process metadata and stores process snapshots.
- Detection: Detection components analyse filesystem activity and evaluate suspicious behaviour using configured thresholds.
- Threat scoring: A weighted scoring mechanism evaluates triggered signals and determines threat scores and threat levels.
- Incident management: Critical detections can generate incident records, alerts and threat-score records.
- Reporting: Incident information can be exported in JSON and CSV formats.
- Dashboard: A browser-based interface displays system status, alerts, filesystem events, modified files, CPU and entropy charts.

SQLite provides persistent local storage, while FastAPI exposes application functionality through REST endpoints.

## 3. Testing Methodology and Results

Testing included unit tests, integration tests, API verification and controlled filesystem simulation.

The application was tested using disposable files inside an isolated sandbox. A simulated activity created 50 files, modified their contents with random data, and renamed them using a .locked extension.

The detection pipeline generated a CRITICAL incident with a threat score of 95/100. The incident included affected-file information and generated a security alert.

Health, status, alerts, events, reports, manual scanning and configuration-update API endpoints were also verified.

Automated test results:
- Tests collected: 244
- Tests passed: 244
- Tests failed: 0
- Code coverage: 79%

JSON and CSV incident report generation were successfully verified.

## 4. False-Positive Considerations

Legitimate applications can generate filesystem activity resembling ransomware behaviour.

For example, backup utilities and file compression applications may modify or rename many files within a short period. Such activity could potentially trigger suspicious modification or mass-rename signals.

RDRS uses configurable thresholds and weighted threat scoring to evaluate suspicious activity. Further testing against legitimate high-volume file operations would help improve detection accuracy and reduce false positives.

## 5. Safety and Limitations

Testing was performed using simulated filesystem activity rather than actual ransomware or malware. Simulation mode remained enabled and process termination was disabled.

Automated evidence copying and quarantine handling are not implemented in the current version. Suspect-process attribution is also not consistently available for incidents.

## 6. Future Improvements

Potential improvements include safe evidence preservation, better process-to-incident attribution, increased automated test coverage, PDF reporting, improved false-positive handling and Docker-based deployment.
