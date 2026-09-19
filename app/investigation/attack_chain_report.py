from app.event_model import SecurityEvent


STAGE_CONFIG = {
    "LOGIN_SUCCESS": {
        "stage": "INITIAL_ACCESS",
        "description": "A successful authentication event was observed.",
        "mitre_technique": "T1078",
        "mitre_name": "Valid Accounts",
        "tactic": "Initial Access",
        "risk": 10,
        "confidence": 0.80,
    },
    "PRIVILEGE_GRANTED": {
        "stage": "PRIVILEGE_ESCALATION",
        "description": "Elevated privileges were granted.",
        "mitre_technique": "T1548",
        "mitre_name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
        "risk": 30,
        "confidence": 0.92,
    },
    "PROCESS_STARTED": {
        "stage": "EXECUTION",
        "description": "A process execution event was observed.",
        "mitre_technique": "T1059",
        "mitre_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "risk": 15,
        "confidence": 0.88,
    },
    "DNS_QUERY": {
        "stage": "DISCOVERY_OR_C2",
        "description": "DNS activity was observed.",
        "mitre_technique": "T1071",
        "mitre_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "risk": 10,
        "confidence": 0.85,
    },
    "NETWORK_CONNECTION": {
        "stage": "NETWORK_ACTIVITY",
        "description": "An outbound network connection was observed.",
        "mitre_technique": "T1071",
        "mitre_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "risk": 15,
        "confidence": 0.87,
    },
}


def generate_attack_chain_report(
    events: list[SecurityEvent],
) -> dict:
    events = sorted(
        events,
        key=lambda event: event.timestamp,
    )

    stages = []
    total_risk = 0
    confidence_values = []

    for event in events:

        config = STAGE_CONFIG.get(event.event_type)

        if config is None:
            continue

        stage_data = {
            "stage": config["stage"],
            "timestamp": event.timestamp.isoformat(),
            "event_type": event.event_type,
            "source_ip": event.source_ip,
            "username": event.username,
            "host": event.host,
            "description": config["description"],
            "mitre_technique": config["mitre_technique"],
            "mitre_name": config["mitre_name"],
            "tactic": config["tactic"],
            "risk": config["risk"],
            "confidence": config["confidence"],
            "evidence": {
                "event_type": event.event_type,
                "timestamp": event.timestamp.isoformat(),
                "source_ip": event.source_ip,
                "username": event.username,
                "host": event.host,
            },
        }

        stages.append(stage_data)

        total_risk += config["risk"]
        confidence_values.append(config["confidence"])

    average_confidence = (
        sum(confidence_values) / len(confidence_values)
        if confidence_values
        else 0.0
    )

    return {
        "detected": len(stages) >= 2,
        "stage_count": len(stages),
        "stages": stages,
        "total_risk": min(total_risk, 100),
        "confidence": average_confidence,
    }