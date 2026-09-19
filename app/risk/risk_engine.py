from app.event_model import SecurityEvent


SEVERITY_POINTS = {
    "low": 5,
    "medium": 15,
    "high": 25,
    "critical": 35,
}

SEVERITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def calculate_risk(
    events: list[SecurityEvent],
    confidence: float,
) -> int:
    if not events:
        return 0

    highest_severity = max(
        (event.severity.lower() for event in events),
        key=lambda severity: SEVERITY_ORDER.get(severity, 0),
    )

    score = SEVERITY_POINTS.get(highest_severity, 0)

    event_types = {event.event_type for event in events}

    failed_count = sum(
        1
        for event in events
        if event.event_type == "LOGIN_FAILED"
    )

    # Strong behavioral indicators
    if failed_count >= 5:
        score += 20

    if failed_count >= 3 and "LOGIN_SUCCESS" in event_types:
        score += 25

    if "PRIVILEGE_GRANTED" in event_types:
        score += 30

    if "PROCESS_STARTED" in event_types:
        score += 15

    if "NETWORK_CONNECTION" in event_types:
        score += 15

    if "DNS_QUERY" in event_types:
        score += 10

    score += int(confidence * 10)

    # Important behavior floors
    if "PRIVILEGE_GRANTED" in event_types:
        score = max(score, 70)

    if failed_count >= 5 and "LOGIN_SUCCESS" in event_types:
        score = max(score, 75)

    return min(score, 100)