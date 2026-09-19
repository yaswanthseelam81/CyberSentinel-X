VALID_STATUSES = {
    "OPEN",
    "INVESTIGATING",
    "CONTAINED",
    "RESOLVED",
}


def update_status(case: dict, new_status: str) -> dict:
    new_status = new_status.upper()

    if new_status not in VALID_STATUSES:
        raise ValueError(f"Invalid status: {new_status}")

    case["status"] = new_status

    return case