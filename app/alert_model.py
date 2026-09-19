from dataclasses import dataclass
from datetime import datetime


@dataclass
class SecurityAlert:
    alert_id: str
    timestamp: datetime
    alert_type: str
    source_ip: str
    username: str
    host: str
    severity: str
    confidence: float
    risk_score: int
    risk_level: str
    mitre_technique_id: str
    mitre_technique_name: str
    mitre_tactic: str
    description: str
    evidence: list[str]