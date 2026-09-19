from app.collectors.log_reader import read_log_file
from app.normalizer.log_parser import parse_log_line
from app.correlation.event_correlator import correlate_events
from app.incident_builder import build_incident


logs = read_log_file("data/security.log")
events = [parse_log_line(log) for log in logs]

incident_groups = correlate_events(events)

for group in incident_groups:
    incident = build_incident(group)

    print("\nINCIDENT CREATED")
    print(f"ID: {incident.incident_id}")
    print(f"Source IP: {incident.source_ip}")
    print(f"User: {incident.username}")
    print(f"Host: {incident.host}")
    print(f"Events: {incident.event_count}")
    print(f"Status: {incident.status}")
    print(f"Severity: {incident.severity}")