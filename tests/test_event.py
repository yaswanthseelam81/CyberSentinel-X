from datetime import datetime
from app.event_model import SecurityEvent


event = SecurityEvent(
    timestamp=datetime.now(),
    event_type="LOGIN_FAILED",
    username="yash",
    source_ip="192.168.1.50",
    host="kali-lab",
    severity="medium",
)

print(event)