from dataclasses import dataclass
from datetime import datetime

from app.event_model import SecurityEvent


@dataclass
class SecurityIncident:
    incident_id: str
    created_at: datetime
    source_ip: str
    username: str
    host: str
    event_count: int
    events: list[SecurityEvent]
    status: str
    severity: str