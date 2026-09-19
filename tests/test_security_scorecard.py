from app.evaluation.scenario_runner import run_all_scenarios
from app.collectors.log_reader import read_log_file
from app.normalizer.log_parser import parse_log_line
from app.detection.rule_manager import load_all_rules
from app.detection.rule_engine import evaluate_rule


# Attack scenarios
attack_results = run_all_scenarios()

attack_passed = sum(
    1 for result in attack_results
    if result["detected"]
)


# Normal activity
logs = read_log_file("data/normal_activity.log")
events = [parse_log_line(log) for log in logs]

rules = load_all_rules("rules")

normal_alerts = []

for rule in rules:
    normal_alerts.extend(
        evaluate_rule(events, rule)
    )


total_attacks = len(attack_results)
detection_rate = (
    attack_passed / total_attacks * 100
    if total_attacks
    else 0
)

false_positive_rate = (
    100
    if normal_alerts
    else 0
)


print("\n=== CYBERSENTINEL SECURITY SCORECARD ===")
print(f"Attack Scenarios      : {total_attacks}")
print(f"Detected              : {attack_passed}")
print(f"Detection Rate        : {detection_rate:.1f}%")
print(f"Normal Alerts         : {len(normal_alerts)}")
print(f"False Positive Rate   : {false_positive_rate:.1f}%")

if detection_rate >= 80 and not normal_alerts:
    print("\nOVERALL RESULT: PASS")
else:
    print("\nOVERALL RESULT: REVIEW")