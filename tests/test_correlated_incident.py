from app.collectors.log_reader import read_log_file
from app.normalizer.log_parser import parse_log_line
from app.detection.rule_loader import load_rule
from app.detection.rule_engine import evaluate_rule
from app.correlation.alert_correlator import correlate_alerts
from app.correlation.correlated_incident import build_correlated_incident


logs = read_log_file("data/security.log")
events = [parse_log_line(log) for log in logs]

rules = [
    load_rule("rules/brute_force.json"),
    load_rule("rules/suspicious_login.json"),
]

alerts = []

for rule in rules:
    alerts.extend(evaluate_rule(events, rule))

groups = correlate_alerts(alerts)

for group in groups:
    incident = build_correlated_incident(group)

    print("\nCORRELATED INCIDENT")
    print(f"ID: {incident['incident_id']}")
    print(f"Source IP: {incident['source_ip']}")
    print(f"Alerts: {incident['alert_count']}")
    print(f"Severity: {incident['severity']}")
    print(f"Status: {incident['status']}")