from datetime import datetime

from app.event_model import SecurityEvent


def parse_log_line(line: str) -> SecurityEvent:
    parts = line.split()

    timestamp = datetime.strptime(
        f"{parts[0]} {parts[1]}",
        "%Y-%m-%d %H:%M:%S",
    )

    event_type = parts[2]

    data = {}

    for part in parts[3:]:
        key, value = part.split("=", 1)
        data[key] = value

    severity = "medium"

    if event_type == "LOGIN_SUCCESS":
        severity = "low"

    return SecurityEvent(
        timestamp=timestamp,
        event_type=event_type,
        username=data["user"],
        source_ip=data["ip"],
        host=data["host"],
        severity=severity,
        process=data.get("process")
    )