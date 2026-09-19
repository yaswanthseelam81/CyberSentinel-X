from dataclasses import dataclass


@dataclass
class PipelineResult:
    event_count: int
    alert_count: int
    incident_count: int
    incidents: list[dict]