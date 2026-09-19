from app.collectors.log_reader import read_log_file
from app.normalizer.log_parser import parse_log_line
from app.incident_intelligence import build_incident_intelligence
from app.reports.incident_report import generate_report


logs = read_log_file("data/security.log")
events = [parse_log_line(log) for log in logs]

intelligence = build_incident_intelligence(events)

report = generate_report(intelligence)

print(report)