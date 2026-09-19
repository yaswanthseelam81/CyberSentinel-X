from datetime import datetime

from app.event_model import SecurityEvent
from app.incident_model import SecurityIncident


event = SecurityEvent(
    timestamp=datetime.now(),
    event_type="LOGIN_FAILED",
    username="yash",
    source_ip="192.168.1.50",
    host="kali-lab",
    severity="medium",
)

incident = SecurityIncident(
    incident_id="INC-0001",
    created_at=datetime.now(),
    source_ip="192.168.1.50",
    username="yash",
    host="kali-lab",
    event_count=1,
    events=[event],
    status="OPEN",
    severity="HIGH",
)

print(incident)