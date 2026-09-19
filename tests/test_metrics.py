from app.evaluation.metrics import ScenarioResult, calculate_metrics


results = [
    ScenarioResult("Brute Force", True, True),
    ScenarioResult("Privilege Escalation", True, True),
    ScenarioResult("Suspicious Process", True, True),
    ScenarioResult("Suspicious DNS", True, True),
    ScenarioResult("Unusual Network", True, True),
]

metrics = calculate_metrics(results)

print("\n=== CYBERSENTINEL DETECTION METRICS ===")
print(f"Scenarios       : {metrics['total']}")
print(f"Passed          : {metrics['passed']}")
print(f"Failed          : {metrics['failed']}")
print(f"Detection Rate  : {metrics['detection_rate']:.1f}%")