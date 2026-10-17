# WindowsEventLens — Windows Event Log Analyzer

**Day 14/100 · 100 Days • 100 Cybersecurity Projects**

WindowsEventLens is an offline-first Python CLI that analyzes exported Windows event records in JSON format and surfaces review-worthy authentication and account-management activity with evidence and remediation guidance.

## What it does
- Counts event IDs and summarizes analyzed records.
- Flags repeated Event ID **4625** failed logons by source IP and target account (configurable threshold).
- Highlights Event ID **1102** (Security audit log cleared) and **4720** (user account created).
- Produces JSON reports and optional CSV findings.
- Includes a synthetic lab fixture and standard-library unit tests.

## Requirements
- Python 3.10+
- No third-party dependencies.

## Run (Windows PowerShell)
```powershell
py -m unittest discover -s tests -v
py windowseventlens.py samples/sample_events.json --output reports/demo-report.json --csv reports/findings.csv
```

## Run (Linux/macOS/Kali)
```bash
python3 -m unittest discover -s tests -v
python3 windowseventlens.py samples/sample_events.json --output reports/demo-report.json --csv reports/findings.csv
```

Change the repeated-failure threshold:
```bash
python3 windowseventlens.py samples/sample_events.json --threshold 3
```

## Input format
Supply a JSON array of objects, or an object with an `events` array. Preferred normalized keys are `event_id`, `timestamp`, `target_user`, `ip_address`, `computer`, and `logon_type`. A small subset of exported field names (`EventID`, `TargetUserName`, `IpAddress`, `Computer`, `LogonType`) is also accepted.

To use real Windows logs, export the relevant Security log records from Event Viewer or another authorized collection workflow into JSON matching this schema. This version does **not** connect to Windows Event Log APIs or collect events directly.

## Detection notes
- Event IDs are interpreted in context; auditing policy, Windows version, logon type, and surrounding events matter.
- IP fan-out rules use simple counts, not time-window correlation. Repeated failures can be caused by stale services, misconfiguration, or legitimate user errors.
- Findings are triage leads, not proof of compromise. Validate against approved administrative activity and corroborating telemetry.
- The tool does not perform live monitoring, network activity, remediation, credential collection, or event-log modification.
- This is an educational analyzer, not a SIEM replacement or complete Windows event parser.

## Project structure
```text
WindowsEventLens/
├── windowseventlens.py
├── samples/sample_events.json
├── tests/test_windowseventlens.py
├── reports/.gitkeep
├── requirements.txt
├── README.md
└── LICENSE
```

## License
MIT
