from app.collectors.log_reader import read_log_file
from app.normalizer.log_parser import parse_log_line
from app.detection.rule_manager import load_all_rules
from app.detection.rule_engine import evaluate_rule


logs = read_log_file("data/normal_activity.log")
events = [parse_log_line(log) for log in logs]

rules = load_all_rules("rules")

alerts = []

for rule in rules:
    alerts.extend(
        evaluate_rule(events, rule)
    )

print("\n=== FALSE POSITIVE TEST ===")
print(f"Normal Events : {len(events)}")
print(f"Alerts        : {len(alerts)}")

print("PASS" if len(alerts) == 0 else "FAIL")

for alert in alerts:
    print(alert)