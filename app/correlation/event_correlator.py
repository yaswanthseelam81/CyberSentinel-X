from datetime import timedelta

from app.event_model import SecurityEvent


CORRELATION_WINDOW_MINUTES = 5


def correlate_events(
    events: list[SecurityEvent],
) -> list[list[SecurityEvent]]:
    events = sorted(events, key=lambda event: event.timestamp)

    incidents: list[list[SecurityEvent]] = []

    for event in events:
        added_to_incident = False

        for incident in incidents:
            first_event = incident[0]

            same_source = event.source_ip == first_event.source_ip
            same_user = event.username == first_event.username
            within_window = (
                event.timestamp - first_event.timestamp
                <= timedelta(minutes=CORRELATION_WINDOW_MINUTES)
            )

            if same_source and same_user and within_window:
                incident.append(event)
                added_to_incident = True
                break

        if not added_to_incident:
            incidents.append([event])

    return incidents