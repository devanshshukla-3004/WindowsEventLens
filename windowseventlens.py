#!/usr/bin/env python3
"""WindowsEventLens: offline analyzer for exported Windows Security event records."""
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Common Windows Security event IDs. Interpretation depends on audit policy and context.
EVENTS = {
    4624: ("Successful logon", "INFO"),
    4625: ("Failed logon", "LOW"),
    4634: ("Logoff", "INFO"),
    4648: ("Logon using explicit credentials", "MEDIUM"),
    4672: ("Special privileges assigned to new logon", "MEDIUM"),
    4720: ("User account created", "MEDIUM"),
    4722: ("User account enabled", "MEDIUM"),
    4724: ("Attempt to reset account password", "MEDIUM"),
    4725: ("User account disabled", "MEDIUM"),
    4726: ("User account deleted", "MEDIUM"),
    4740: ("Account locked out", "MEDIUM"),
    1102: ("Security audit log cleared", "HIGH"),
}
SEVERITY_SCORE = {"INFO": 0, "LOW": 20, "MEDIUM": 50, "HIGH": 80, "CRITICAL": 100}


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def normalize(record: dict[str, Any]) -> dict[str, Any]:
    """Accept normalized JSON rows or a small subset of Windows export field names."""
    event_id = _int(record.get("event_id", record.get("EventID", record.get("Id", 0))))
    timestamp = str(record.get("timestamp", record.get("TimeCreated", record.get("time", "unknown"))))
    user = str(record.get("target_user", record.get("TargetUserName", record.get("user", "unknown"))))
    ip = str(record.get("ip_address", record.get("IpAddress", record.get("source_ip", "unknown"))))
    host = str(record.get("computer", record.get("Computer", record.get("host", "unknown"))))
    logon_type = str(record.get("logon_type", record.get("LogonType", "unknown")))
    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "target_user": user,
        "ip_address": ip,
        "computer": host,
        "logon_type": logon_type,
        "description": EVENTS.get(event_id, ("Unmapped event", "INFO"))[0],
    }


def analyze(records: list[dict[str, Any]], threshold: int = 5) -> dict[str, Any]:
    events = [normalize(record) for record in records]
    failed_by_ip: Counter[str] = Counter()
    failed_by_user: Counter[str] = Counter()

    for event in events:
        if event["event_id"] == 4625:
            if event["ip_address"] not in ("", "unknown", "-", "::1", "127.0.0.1"):
                failed_by_ip[event["ip_address"]] += 1
            if event["target_user"] not in ("", "unknown", "-"):
                failed_by_user[event["target_user"]] += 1

    findings: list[dict[str, Any]] = []
    for ip, count in failed_by_ip.items():
        if count >= threshold:
            findings.append({
                "rule_id": "WEL-001",
                "severity": "HIGH" if count >= threshold * 2 else "MEDIUM",
                "title": "Repeated failed logons from one source",
                "entity": ip,
                "count": count,
                "evidence": f"{count} event 4625 records attributed to source {ip}.",
                "recommendation": "Correlate with successful logons, VPN/proxy context, and approved admin activity before escalation.",
            })
    for user, count in failed_by_user.items():
        if count >= threshold:
            findings.append({
                "rule_id": "WEL-002",
                "severity": "MEDIUM",
                "title": "Repeated failed logons against one account",
                "entity": user,
                "count": count,
                "evidence": f"{count} event 4625 records target account {user}.",
                "recommendation": "Check for mistyped credentials, stale services, and password-spraying patterns; follow identity response procedures.",
            })

    for event in events:
        if event["event_id"] == 1102:
            findings.append({
                "rule_id": "WEL-003", "severity": "HIGH",
                "title": "Security audit log cleared", "entity": event["computer"], "count": 1,
                "evidence": f"Event 1102 recorded at {event['timestamp']} on {event['computer']}.",
                "recommendation": "Verify authorized maintenance and preserve adjacent event logs; log clearing alone does not prove malicious activity.",
            })
        elif event["event_id"] == 4720:
            findings.append({
                "rule_id": "WEL-004", "severity": "MEDIUM",
                "title": "User account created", "entity": event["target_user"], "count": 1,
                "evidence": f"Event 4720 recorded at {event['timestamp']}.",
                "recommendation": "Confirm the account creation request and review assigned groups/privileges.",
            })

    findings.sort(key=lambda finding: (-SEVERITY_SCORE[finding["severity"]], finding["rule_id"], finding["entity"]))
    event_counts = Counter(str(event["event_id"]) for event in events)
    severity_counts = Counter(finding["severity"] for finding in findings)
    average_score = round(sum(SEVERITY_SCORE[f["severity"]] for f in findings) / len(findings)) if findings else 0
    return {
        "tool": "WindowsEventLens",
        "version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_events": len(events),
            "unique_event_ids": len(event_counts),
            "findings": len(findings),
            "severity_counts": dict(severity_counts),
            "average_finding_score": average_score,
        },
        "event_id_counts": dict(sorted(event_counts.items(), key=lambda item: int(item[0]))),
        "findings": findings,
        "events": events,
        "limitations": [
            "Offline analysis of supplied exported records only.",
            "Heuristic findings require human validation and are not proof of compromise.",
            "This is not a replacement for a SIEM or complete Windows event parser.",
        ],
    }


def load_records(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if isinstance(data, dict):
        data = data.get("events", data.get("records", []))
    if not isinstance(data, list) or any(not isinstance(item, dict) for item in data):
        raise ValueError("Input must be a JSON array of event objects, or an object containing an 'events' array.")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze exported Windows event records offline (JSON input).")
    parser.add_argument("input", type=Path, help="Path to JSON event records")
    parser.add_argument("--threshold", type=int, default=5, help="Failed-logon threshold (default: 5)")
    parser.add_argument("--output", type=Path, default=Path("reports/windowseventlens-report.json"), help="JSON report path")
    parser.add_argument("--csv", type=Path, help="Optional findings CSV output path")
    args = parser.parse_args()
    if args.threshold < 2:
        parser.error("--threshold must be at least 2")
    try:
        report = analyze(load_records(args.input), args.threshold)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        parser.error(str(exc))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    if args.csv:
        args.csv.parent.mkdir(parents=True, exist_ok=True)
        fields = ["rule_id", "severity", "title", "entity", "count", "evidence", "recommendation"]
        with args.csv.open("w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=fields)
            writer.writeheader()
            writer.writerows(report["findings"])

    print(f"WindowsEventLens v{report['version']} — Offline Event Analysis")
    print(f"Events: {report['summary']['total_events']} | Event IDs: {report['summary']['unique_event_ids']} | Findings: {report['summary']['findings']}")
    print(f"Report: {args.output}")
    for finding in report["findings"]:
        print(f"[{finding['severity']}] {finding['title']} — {finding['entity']} ({finding['count']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
