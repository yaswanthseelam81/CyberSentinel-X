TECHNIQUE_MAP = {
    "BRUTE_FORCE": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
    },
    "ACCOUNT_COMPROMISE": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
    },
    "PRIV_ESC": {
        "technique_id": "T1548",
        "technique_name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
    },
}


def get_technique(alert_type: str) -> dict | None:
    return TECHNIQUE_MAP.get(alert_type)