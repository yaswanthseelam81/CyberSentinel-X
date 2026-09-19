from app.collectors.log_reader import read_log_file
from app.normalizer.log_parser import parse_log_line
from app.detection.rule_manager import load_all_rules
from app.detection.rule_engine import evaluate_rule
from app.correlation.alert_correlator import correlate_alerts
from app.correlation.correlated_incident import build_correlated_incident
from app.incident_enricher import enrich_incident


SCENARIOS = {
    "Brute Force": "data/simulated_attack.log",
    "Privilege Escalation": "data/privilege_escalation.log",
    "Suspicious Process": "data/suspicious_process.log",
    "Suspicious DNS": "data/suspicious_dns.log",
    "Unusual Network": "data/unusual_network.log",
}


rules = load_all_rules("rules")


print("\n=== CYBERSENTINEL RISK CALIBRATION ===")

for name, log_file in SCENARIOS.items():

    logs = read_log_file(log_file)
    events = [parse_log_line(log) for log in logs]

    alerts = []

    for rule in rules:
        alerts.extend(
            evaluate_rule(events, rule)
        )

    groups = correlate_alerts(alerts)

    if not groups:
        print(f"{name:<22} NO INCIDENT")
        continue

    incident = build_correlated_incident(groups[0])

    enriched = enrich_incident(
        events,
        groups[0],
        incident,
    )

    print(
        f"{name:<22} "
        f"Risk: {enriched['risk_score']:>3}/100 | "
        f"Level: {enriched['risk_level']:<8} | "
        f"Severity: {enriched['severity']}"
    )