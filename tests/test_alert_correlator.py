from app.collectors.log_reader import read_log_file
from app.normalizer.log_parser import parse_log_line
from app.detection.rule_loader import load_rule
from app.detection.rule_engine import evaluate_rule
from app.correlation.alert_correlator import correlate_alerts


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

for number, group in enumerate(groups, start=1):
    print(f"\nCORRELATED GROUP {number}")

    for alert in group:
        print(
            f"{alert['rule_id']} | "
            f"{alert['severity']} | "
            f"{alert['source_ip']}"
        )