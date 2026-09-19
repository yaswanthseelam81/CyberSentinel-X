from app.collectors.log_reader import read_log_file
from app.normalizer.log_parser import parse_log_line
from app.detection.rule_manager import load_all_rules
from app.detection.rule_engine import evaluate_rule
from app.correlation.alert_correlator import correlate_alerts
from app.correlation.correlated_incident import build_correlated_incident
from app.incident_enricher import enrich_incident


logs = read_log_file("data/privilege_escalation.log")
events = [parse_log_line(log) for log in logs]

rules = load_all_rules("rules")

alerts = []

for rule in rules:
    alerts.extend(
        evaluate_rule(events, rule)
    )

groups = correlate_alerts(alerts)

incident = build_correlated_incident(groups[0])

enriched = enrich_incident(
    events,
    groups[0],
    incident,
)

print("\n=== PRIVILEGE ESCALATION INCIDENT ===")
print(f"Incident : {enriched['incident_id']}")
print(f"Severity : {enriched['severity']}")
print(f"Risk     : {enriched['risk_score']}/100")
print(f"Level    : {enriched['risk_level']}")
print(f"MITRE    : {enriched['mitre']}")
print(f"Narrative: {enriched['narrative']}")