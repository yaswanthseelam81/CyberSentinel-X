from app.investigation.actions import add_action


case = {
    "case_id": "CASE-0001",
    "status": "OPEN",
}

case = add_action(
    case,
    "Investigating",
    "Analyst started investigation.",
)

case = add_action(
    case,
    "Contained",
    "Source IP blocked and affected host isolated.",
)

print("\n=== INVESTIGATION ACTIONS ===")

print(f"Status: {case['status']}")

for action in case["actions"]:
    print(
        f"{action['action']} -> "
        f"{action['note']}"
    )