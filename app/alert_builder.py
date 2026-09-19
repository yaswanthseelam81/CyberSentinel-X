from datetime import datetime

from app.alert_model import SecurityAlert
from app.risk.risk_level import get_risk_level
from app.mitre.technique_map import get_technique

def build_brute_force_alert(
    source_ip: str,
    username: str,
    host: str,
    failed_attempts: int,
    window_minutes: int,
    risk_score: int,
) -> SecurityAlert:
    risk_level = get_risk_level(risk_score)
    technique = get_technique("BRUTE_FORCE")
    if technique is None:
        raise ValueError("MITRE technique mapping not found.")
    return SecurityAlert(
        alert_id=f"CS-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        timestamp=datetime.now(),
        alert_type="BRUTE_FORCE",
        source_ip=source_ip,
        username=username,
        host=host,
        severity="high",
        confidence=0.95,
        risk_score=risk_score,
        risk_level=risk_level,
        mitre_technique_id=technique["technique_id"],
        mitre_technique_name=technique["technique_name"],
        mitre_tactic=technique["tactic"],
        description=(
            f"{failed_attempts} failed login attempts detected "
            f"from the same source within {window_minutes} minutes."
        ),
        evidence=[
            f"Failed attempts: {failed_attempts}",
            f"Source IP: {source_ip}",
            f"Time window: {window_minutes} minutes",
        ],
    )