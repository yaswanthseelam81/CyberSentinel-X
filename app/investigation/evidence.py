from app.event_model import SecurityEvent


def collect_evidence(events: list[SecurityEvent]) -> list[dict]:
    evidence = []

    for event in events:
        evidence.append(
            {
                "timestamp": event.timestamp.isoformat(),
                "event_type": event.event_type,
                "username": event.username,
                "source_ip": event.source_ip,
                "host": event.host,
                "severity": event.severity,
            }
        )

    return evidence