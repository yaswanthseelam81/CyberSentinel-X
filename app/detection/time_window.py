from datetime import timedelta

from app.event_model import SecurityEvent


def events_within_window(
    events: list[SecurityEvent],
    window_minutes: int,
) -> list[list[SecurityEvent]]:
    events = sorted(events, key=lambda event: event.timestamp)

    groups = []

    for event in events:
        added = False

        for group in groups:
            if event.timestamp - group[0].timestamp <= timedelta(
                minutes=window_minutes
            ):
                group.append(event)
                added = True
                break

        if not added:
            groups.append([event])

    return groups