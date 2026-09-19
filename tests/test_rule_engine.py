from app.collectors.log_reader import read_log_file
from app.normalizer.log_parser import parse_log_line
from app.detection.rule_loader import load_rule
from app.detection.rule_engine import evaluate_rule


logs = read_log_file("data/security.log")
events = [parse_log_line(log) for log in logs]

rules = [
    load_rule("rules/brute_force.json"),
    load_rule("rules/suspicious_login.json"),
]

for rule in rules:
    print(f"\nRULE: {rule['rule_id']}")

    alerts = evaluate_rule(events, rule)

    for alert in alerts:
        print(alert)