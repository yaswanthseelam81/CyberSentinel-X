from app.collectors.log_reader import read_log_file
from app.normalizer.log_parser import parse_log_line
from app.detection.rule_loader import load_rule
from app.detection.rule_engine import evaluate_rule


logs = read_log_file("data/suspicious_process.log")
events = [parse_log_line(log) for log in logs]

rule = load_rule("rules/suspicious_process.json")

alerts = evaluate_rule(events, rule)

for alert in alerts:
    print(alert)