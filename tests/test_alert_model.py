from datetime import datetime

from app.alert_model import SecurityAlert


alert = SecurityAlert(
    alert_id="CS-0001",
    timestamp=datetime.now(),
    alert_type="BRUTE_FORCE",
    source_ip="192.168.1.50",
    username="yash",
    host="kali-lab",
    severity="high",
    confidence=0.95,
    description="Multiple failed login attempts detected from the same source IP within a short time window.",
    evidence=[
        "5 failed login attempts",
        "Same source IP: 192.168.1.50",
        "Activity occurred within 5 minutes",
    ],
)

print(alert)