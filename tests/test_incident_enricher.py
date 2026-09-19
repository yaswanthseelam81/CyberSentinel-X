from app.collectors.log_reader import read_log_file
from app.normalizer.log_parser import parse_log_line
from app.detection.rule_manager import load_all_rules
from app.detection.rule_engine import evaluate_rule
from app.correlation.alert_correlator import correlate_alerts
from app.correlation.correlated_incident import build_correlated_incident
from app.incident_enricher import enrich_incident


logs = read_log_file("data/full_attack_chain.log")
events = [parse_log_line(log) for log in logs]

rules = load_all_rules("rules")

alerts = []

for rule in rules:
    alerts.extend(evaluate_rule(events, rule))

groups = correlate_alerts(alerts)

incident = build_correlated_incident(groups[0])

enriched = enrich_incident(
    events,
    groups[0],
    incident,
)

print("\n=== ENRICHED INCIDENT ===")
print(f"ID         : {enriched['incident_id']}")
print(f"Source IP  : {enriched['source_ip']}")
print(f"Severity   : {enriched['severity']}")
print(f"Risk       : {enriched['risk_score']}/100")
print(f"Risk Level : {enriched['risk_level']}")
print(f"Confidence : {enriched['confidence'] * 100:.0f}%")
print(f"Evidence   : {len(enriched['evidence'])}")
print(f"Timeline   : {len(enriched['timeline'])}")

print("\nMITRE")
print(enriched["mitre"])

print("\nNARRATIVE")
print(enriched["narrative"])
print("\nATTACK CHAIN")

chain = enriched["attack_chain"]

print(f"Detected: {chain['detected']}")
print(f"Stages: {chain['stage_count']}")

for stage in chain["stages"]:
    print(
        f"{stage['timestamp']} | "
        f"{stage['stage']} | "
        f"{stage['description']}"
    )