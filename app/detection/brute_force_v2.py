from collections import Counter
from datetime import timedelta

from app.event_model import SecurityEvent


FAILED_LOGIN_THRESHOLD = 5
WINDOW_MINUTES = 5


def detect_brute_force(events: list[SecurityEvent]) -> list[dict]:
    failed_events = [
        event
        for event in events
        if event.event_type == "LOGIN_FAILED"
    ]

    failed_events.sort(key=lambda event: event.timestamp)

    alerts = []

    for i, start_event in enumerate(failed_events):
        window_end = start_event.timestamp + timedelta(minutes=WINDOW_MINUTES)

        window_events = [
            event
            for event in failed_events[i:]
            if event.timestamp <= window_end
        ]

        ip_counts = Counter(
            event.source_ip
            for event in window_events
        )

        for ip, count in ip_counts.items():
            if count >= FAILED_LOGIN_THRESHOLD:
                alerts.append(
                    {
                        "alert_type": "BRUTE_FORCE",
                        "source_ip": ip,
                        "failed_attempts": count,
                        "window_minutes": WINDOW_MINUTES,
                        "severity": "high",
                    }
                )

                break

    return alerts