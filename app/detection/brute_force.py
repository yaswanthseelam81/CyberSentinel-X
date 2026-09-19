from collections import Counter
from app.event_model import SecurityEvent


FAILED_LOGIN_THRESHOLD = 5


def detect_brute_force(events: list[SecurityEvent]) -> list[dict]:
    failed_events = [
        event
        for event in events
        if event.event_type == "LOGIN_FAILED"
    ]

    counts = Counter(event.source_ip for event in failed_events)

    alerts = []

    for ip, count in counts.items():
        if count >= FAILED_LOGIN_THRESHOLD:
            alerts.append(
                {
                    "alert_type": "BRUTE_FORCE",
                    "source_ip": ip,
                    "failed_attempts": count,
                    "severity": "high",
                }
            )

    return alerts