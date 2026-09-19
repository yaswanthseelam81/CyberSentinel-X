from app.event_model import SecurityEvent
from app.investigation.attack_narrative import generate_attack_narrative
from app.investigation.timeline import build_timeline
from app.mitre.technique_map import get_technique
from app.risk.risk_engine import calculate_risk
from app.risk.risk_level import get_risk_level


def build_incident_intelligence(
    events: list[SecurityEvent],
) -> dict:
    if not events:
        raise ValueError("Cannot build intelligence without events.")

    failed_logins = [
        event
        for event in events
        if event.event_type == "LOGIN_FAILED"
    ]

    confidence = 0.95 if len(failed_logins) >= 5 else 0.50

    risk_score = calculate_risk(events, confidence)
    risk_level = get_risk_level(risk_score)

    technique = None

    if len(failed_logins) >= 5:
        technique = get_technique("BRUTE_FORCE")

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "confidence": confidence,
        "mitre": technique,
        "timeline": build_timeline(events),
        "narrative": generate_attack_narrative(events),
    }