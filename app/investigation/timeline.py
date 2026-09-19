from app.event_model import SecurityEvent


def build_timeline(events: list[SecurityEvent]) -> list[dict]:
    events = sorted(events, key=lambda event: event.timestamp)

    timeline = []

    for event in events:
        timeline.append(
            {
                "timestamp": event.timestamp.isoformat(),
                "event_type": event.event_type,
                "username": event.username,
                "source_ip": event.source_ip,
                "host": event.host,
                "severity": event.severity,
            }
        )

    return timeline