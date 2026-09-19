from app.collectors.log_reader import read_log_file
from app.normalizer.log_parser import parse_log_line
from app.investigation.evidence import collect_evidence
from app.investigation.attack_narrative import generate_attack_narrative
from app.correlation.alert_correlator import correlate_alerts
from app.correlation.correlated_incident import build_correlated_incident
from app.detection.rule_loader import load_rule
from app.detection.rule_engine import evaluate_rule
from app.investigation.case import build_investigation_case


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

incident = build_correlated_incident(groups[0])
evidence = collect_evidence(events)
narrative = generate_attack_narrative(events)

case = build_investigation_case(
    incident,
    evidence,
    narrative,
)

print("\n=== INVESTIGATION CASE ===")
print(f"Case ID: {case['case_id']}")
print(f"Incident ID: {case['incident_id']}")
print(f"Severity: {case['severity']}")
print(f"Source IP: {case['source_ip']}")
print(f"Evidence: {case['evidence_count']}")
print(f"Status: {case['status']}")
print(f"Narrative: {case['narrative']}")