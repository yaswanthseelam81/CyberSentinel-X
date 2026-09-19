from app.investigation.attack_narrative import generate_attack_narrative
from app.investigation.evidence import collect_evidence
from app.investigation.timeline import build_timeline
from app.investigation.attack_chain_report import generate_attack_chain_report
from app.risk.risk_engine import calculate_risk
from app.risk.risk_level import get_risk_level
from app.mitre.technique_map import get_technique


def enrich_incident(
    events: list,
    alerts: list[dict],
    incident: dict,
) -> dict:
    if not events:
        raise ValueError("Cannot enrich an incident without events.")

    confidence = max(
        (
            alert.get("confidence", 0.0)
            for alert in alerts
        ),
        default=0.0,
    )

    risk_score = calculate_risk(
        events,
        confidence,
    )

    risk_level = get_risk_level(
        risk_score
    )

    # -----------------------------
    # MITRE ATT&CK mapping
    # -----------------------------

    mitre = None

    for alert in alerts:
        technique_id = alert.get(
            "mitre_technique"
        )

        if technique_id == "T1110":
            mitre = get_technique(
                "BRUTE_FORCE"
            )
            break

        if technique_id == "T1548":
            mitre = get_technique(
                "PRIV_ESC"
            )
            break

    if mitre is None and alerts:

        technique_map = {
            "T1059": {
                "technique_id": "T1059",
                "technique_name": (
                    "Command and Scripting Interpreter"
                ),
                "tactic": "Execution",
            },
            "T1071": {
                "technique_id": "T1071",
                "technique_name": (
                    "Application Layer Protocol"
                ),
                "tactic": "Command and Control",
            },
        }

        for alert in alerts:
            technique_id = alert.get(
                "mitre_technique"
            )

            if technique_id in technique_map:
                mitre = technique_map[
                    technique_id
                ]
                break

    # -----------------------------
    # Attack Chain
    # -----------------------------

    attack_chain = generate_attack_chain_report(
        events
    )

    # -----------------------------
    # Final enriched incident
    # -----------------------------

    return {
        **incident,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "confidence": confidence,
        "mitre": mitre,
        "timeline": build_timeline(events),
        "evidence": collect_evidence(events),
        "narrative": generate_attack_narrative(events),
        "attack_chain": attack_chain,
    }