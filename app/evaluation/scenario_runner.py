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


def run_scenario(scenario_name: str, log_file: str) -> dict:
    logs = read_log_file(log_file)
    events = [parse_log_line(log) for log in logs]

    rules = load_all_rules("rules")

    alerts = []

    for rule in rules:
        alerts.extend(
            evaluate_rule(events, rule)
        )

    return {
        "scenario": scenario_name,
        "events": len(events),
        "alerts": len(alerts),
        "detected": len(alerts) > 0,
    }


def run_all_scenarios() -> list[dict]:
    results = []

    for name, log_file in SCENARIOS.items():
        results.append(
            run_scenario(name, log_file)
        )

    return results