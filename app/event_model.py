from dataclasses import dataclass
from datetime import datetime


@dataclass
class SecurityEvent:
    timestamp: datetime
    event_type: str
    username: str
    source_ip: str
    host: str
    severity: str
    process: str | None = None