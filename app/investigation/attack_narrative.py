from app.event_model import SecurityEvent


def generate_attack_narrative(events: list[SecurityEvent]) -> str:
    events = sorted(events, key=lambda event: event.timestamp)

    event_types = [event.event_type for event in events]

    failed_logins = event_types.count("LOGIN_FAILED")
    successful_logins = event_types.count("LOGIN_SUCCESS")

    parts = []

    if failed_logins >= 5 and successful_logins:
        parts.append(
            f"{failed_logins} failed login attempts were followed by "
            "a successful login, indicating possible brute-force-driven "
            "account compromise."
        )

    if "PRIVILEGE_GRANTED" in event_types:
        parts.append(
            "A privilege-grant event was observed, indicating possible "
            "privilege escalation."
        )

    if "PROCESS_STARTED" in event_types:
        parts.append(
            "A process execution event was observed and requires "
            "investigation for potentially suspicious execution."
        )

    if "DNS_QUERY" in event_types:
        parts.append(
            "A DNS query associated with the incident was observed."
        )

    if "NETWORK_CONNECTION" in event_types:
        parts.append(
            "An unusual network connection was observed and should "
            "be investigated as possible outbound activity."
        )

    if not parts:
        return "No significant attack sequence detected."

    return " ".join(parts)