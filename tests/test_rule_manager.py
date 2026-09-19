from app.detection.rule_manager import load_all_rules


rules = load_all_rules("rules")

for rule in rules:
    print(
        f"{rule['rule_id']} -> "
        f"{rule['name']}"
    )