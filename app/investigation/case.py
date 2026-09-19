from datetime import datetime


def build_investigation_case(
    incident: dict,
    evidence: list[dict],
    narrative: str,
) -> dict:
    return {
        "case_id": f"CASE-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "incident_id": incident["incident_id"],
        "status": incident["status"],
        "severity": incident["severity"],
        "source_ip": incident["source_ip"],
        "evidence_count": len(evidence),
        "evidence": evidence,
        "narrative": narrative,
    }