from collections import Counter
from datetime import timedelta

from app.event_model import SecurityEvent


def evaluate_rule(
    events: list[SecurityEvent],
    rule: dict,
) -> list[dict]:
    rule_id = rule["rule_id"]

    if rule_id == "BRUTE_FORCE_001":
        return _detect_brute_force(events, rule)

    if rule_id == "SUSPICIOUS_LOGIN_001":
        return _detect_suspicious_login(events, rule)
    if rule_id == "PRIV_ESC_001":
        return _detect_privilege_escalation(events, rule)
    if rule_id == "PROC_EXEC_001":
        return _detect_process_execution(events, rule)
    if rule_id == "DNS_ANOMALY_001":
        return _detect_dns_activity(events, rule)
    if rule_id == "NET_ANOMALY_001":
        return _detect_network_activity(events, rule)

    return []


def _detect_brute_force(
    events: list[SecurityEvent],
    rule: dict,
) -> list[dict]:
    matching_events = [
        event
        for event in events
        if event.event_type == "LOGIN_FAILED"
    ]

    matching_events.sort(key=lambda event: event.timestamp)

    alerts = []

    for i, start_event in enumerate(matching_events):
        window_end = (
            start_event.timestamp
            + timedelta(minutes=rule["window_minutes"])
        )

        window_events = [
            event
            for event in matching_events[i:]
            if event.timestamp <= window_end
        ]

        ip_counts = Counter(
            event.source_ip
            for event in window_events
        )

        for ip, count in ip_counts.items():
            if count >= rule["threshold"]:
                alerts.append(
                    {
                        "rule_id": rule["rule_id"],
                        "rule_name": rule["name"],
                        "source_ip": ip,
                        "event_count": count,
                        "window_minutes": rule["window_minutes"],
                        "severity": rule["severity"],
                        "confidence": rule["confidence"],
                        "mitre_technique": rule["mitre_technique"],
                    }
                )

                return alerts

    return alerts


def _detect_suspicious_login(
    events: list[SecurityEvent],
    rule: dict,
) -> list[dict]:
    events = sorted(events, key=lambda event: event.timestamp)

    alerts = []

    for i, event in enumerate(events):
        if event.event_type != "LOGIN_SUCCESS":
            continue

        window_start = (
            event.timestamp
            - timedelta(minutes=rule["window_minutes"])
        )

        previous_failures = [
            previous_event
            for previous_event in events[:i]
            if (
                previous_event.event_type == "LOGIN_FAILED"
                and previous_event.source_ip == event.source_ip
                and previous_event.username == event.username
                and previous_event.timestamp >= window_start
            )
        ]

        if len(previous_failures) >= rule["failure_threshold"]:
            alerts.append(
                {
                    "rule_id": rule["rule_id"],
                    "rule_name": rule["name"],
                    "source_ip": event.source_ip,
                    "username": event.username,
                    "event_count": len(previous_failures),
                    "window_minutes": rule["window_minutes"],
                    "severity": rule["severity"],
                    "confidence": rule["confidence"],
                    "mitre_technique": rule["mitre_technique"],
                    "finding": "Successful login followed multiple failures",
                }
            )

    return alerts
def _detect_privilege_escalation(
    events: list[SecurityEvent],
    rule: dict,
) -> list[dict]:
    alerts = []

    for event in events:
        if event.event_type == "PRIVILEGE_GRANTED":
            alerts.append(
                {
                    "rule_id": rule["rule_id"],
                    "rule_name": rule["name"],
                    "source_ip": event.source_ip,
                    "username": event.username,
                    "host": event.host,
                    "event_count": 1,
                    "severity": rule["severity"],
                    "confidence": rule["confidence"],
                    "mitre_technique": rule["mitre_technique"],
                    "finding": "Privilege escalation detected",
                }
            )

    return alerts
def _detect_process_execution(
    events: list[SecurityEvent],
    rule: dict,
) -> list[dict]:
    alerts = []

    suspicious_processes = {
        "example_suspicious_process",
        "powershell_encoded",
        "unknown_binary",
    }

    for event in events:
        process_name = getattr(event, "process", None)

        if (
            event.event_type == "PROCESS_STARTED"
            and process_name in suspicious_processes
        ):
            alerts.append(
                {
                    "rule_id": rule["rule_id"],
                    "rule_name": rule["name"],
                    "source_ip": event.source_ip,
                    "username": event.username,
                    "host": event.host,
                    "event_count": 1,
                    "severity": rule["severity"],
                    "confidence": rule["confidence"],
                    "mitre_technique": rule["mitre_technique"],
                    "finding": f"Suspicious process execution: {process_name}",
                }
            )

    return alerts
def _detect_dns_activity(
    events: list[SecurityEvent],
    rule: dict,
) -> list[dict]:
    alerts = []

    for event in events:
        if event.event_type == "DNS_QUERY":
            alerts.append(
                {
                    "rule_id": rule["rule_id"],
                    "rule_name": rule["name"],
                    "source_ip": event.source_ip,
                    "username": event.username,
                    "host": event.host,
                    "event_count": 1,
                    "severity": rule["severity"],
                    "confidence": rule["confidence"],
                    "mitre_technique": rule["mitre_technique"],
                    "finding": "Suspicious DNS activity detected",
                }
            )

    return alerts
def _detect_network_activity(
    events: list[SecurityEvent],
    rule: dict,
) -> list[dict]:
    alerts = []

    for event in events:
        if event.event_type == "NETWORK_CONNECTION":
            alerts.append(
                {
                    "rule_id": rule["rule_id"],
                    "rule_name": rule["name"],
                    "source_ip": event.source_ip,
                    "username": event.username,
                    "host": event.host,
                    "event_count": 1,
                    "severity": rule["severity"],
                    "confidence": rule["confidence"],
                    "mitre_technique": rule["mitre_technique"],
                    "finding": "Unusual network connection detected",
                }
            )

    return alerts