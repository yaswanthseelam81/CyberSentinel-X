from app.collectors.log_reader import read_log_file
from app.normalizer.log_parser import parse_log_line
from app.detection.rule_manager import load_all_rules
from app.detection.rule_engine import evaluate_rule
from app.correlation.alert_correlator import correlate_alerts
from app.correlation.correlated_incident import build_correlated_incident
from app.pipeline_result import PipelineResult


SCENARIO_FILES = [
    "data/simulated_attack.log",
    "data/privilege_escalation.log",
    "data/suspicious_process.log",
    "data/suspicious_dns.log",
    "data/unusual_network.log",
]


def run_pipeline(log_file: str | None = None) -> PipelineResult:
    files = [log_file] if log_file else SCENARIO_FILES

    all_events = []
    all_alerts = []

    rules = load_all_rules("rules")

    for file in files:
        logs = read_log_file(file)
        events = [parse_log_line(log) for log in logs]

        all_events.extend(events)

        for rule in rules:
            all_alerts.extend(
                evaluate_rule(events, rule)
            )

    alert_groups = correlate_alerts(all_alerts)

    incidents = [
        build_correlated_incident(group)
        for group in alert_groups
    ]

    return PipelineResult(
        event_count=len(all_events),
        alert_count=len(all_alerts),
        incident_count=len(incidents),
        incidents=incidents,
    )