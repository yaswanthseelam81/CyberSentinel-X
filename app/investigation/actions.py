VALID_ACTIONS = {
    "Investigating",
    "Contained",
    "Resolved",
}


def add_action(
    case: dict,
    action: str,
    note: str,
) -> dict:
    action = action.title()

    if action not in VALID_ACTIONS:
        raise ValueError(f"Invalid action: {action}")

    case.setdefault("actions", [])

    case["actions"].append(
        {
            "action": action,
            "note": note,
        }
    )

    case["status"] = action

    return case