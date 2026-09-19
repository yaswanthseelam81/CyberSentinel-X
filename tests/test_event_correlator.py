from app.collectors.log_reader import read_log_file
from app.normalizer.log_parser import parse_log_line
from app.correlation.event_correlator import correlate_events


logs = read_log_file("data/security.log")
events = [parse_log_line(log) for log in logs]

incidents = correlate_events(events)

for number, incident in enumerate(incidents, start=1):
    print(f"\nIncident {number}")

    for event in incident:
        print(
            f"{event.timestamp} - "
            f"{event.event_type} - "
            f"{event.source_ip}"
        )