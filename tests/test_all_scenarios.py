from app.collectors.log_reader import read_log_file
from app.normalizer.log_parser import parse_log_line
from app.detection.rule_manager import load_all_rules
from app.detection.rule_engine import evaluate_rule


SCENARIOS = {
    "Brute Force": "data/simulated_attack.log",
    "Privilege Escalation": "data/privilege_escalation.log",
    "Suspicious Process": "data/suspicious_process.log",
    "Suspicious DNS": "data/suspicious_dns.log",
    "Unusual Network": "data/unusual_network.log",
}


rules = load_all_rules("rules")


for scenario_name, log_file in SCENARIOS.items():
    logs = read_log_file(log_file)
    events = [parse_log_line(log) for log in logs]

    alerts = []

    for rule in rules:
        alerts.extend(
            evaluate_rule(events, rule)
        )

    print(f"\n=== {scenario_name} ===")
    print(f"Events : {len(events)}")
    print(f"Alerts : {len(alerts)}")

    for alert in alerts:
        print(
            f"{alert['rule_id']} | "
            f"{alert['severity']} | "
            f"{alert['confidence'] * 100:.0f}%"
        )