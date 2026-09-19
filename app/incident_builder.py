from datetime import datetime

from app.event_model import SecurityEvent
from app.incident_model import SecurityIncident


def build_incident(
    events: list[SecurityEvent],
    severity: str = "HIGH",
) -> SecurityIncident:
    if not events:
        raise ValueError("Cannot create an incident without events.")

    events = sorted(events, key=lambda event: event.timestamp)

    first_event = events[0]

    return SecurityIncident(
        incident_id=f"INC-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        created_at=datetime.now(),
        source_ip=first_event.source_ip,
        username=first_event.username,
        host=first_event.host,
        event_count=len(events),
        events=events,
        status="OPEN",
        severity=severity,
    )