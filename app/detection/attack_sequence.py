from app.event_model import SecurityEvent


def detect_login_compromise_sequence(
    events: list[SecurityEvent],
    failed_threshold: int = 5,
) -> dict | None:
    events = sorted(events, key=lambda event: event.timestamp)

    for i, event in enumerate(events):
        if event.event_type != "LOGIN_SUCCESS":
            continue

        previous_events = events[:i]

        failed_attempts = [
            previous_event
            for previous_event in previous_events
            if (
                previous_event.event_type == "LOGIN_FAILED"
                and previous_event.source_ip == event.source_ip
                and previous_event.username == event.username
            )
        ]

        if len(failed_attempts) >= failed_threshold:
            return {
                "sequence": [
                    "LOGIN_FAILED",
                    "LOGIN_FAILED",
                    "LOGIN_FAILED",
                    "LOGIN_FAILED",
                    "LOGIN_FAILED",
                    "LOGIN_SUCCESS",
                ],
                "source_ip": event.source_ip,
                "username": event.username,
                "failed_attempts": len(failed_attempts),
                "event_time": event.timestamp.isoformat(),
                "finding": "Possible account compromise",
                "severity": "critical",
            }

    return None