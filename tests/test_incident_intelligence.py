from app.collectors.log_reader import read_log_file
from app.normalizer.log_parser import parse_log_line
from app.incident_intelligence import build_incident_intelligence


logs = read_log_file("data/security.log")
events = [parse_log_line(log) for log in logs]

intelligence = build_incident_intelligence(events)

print("\n=== CYBERSENTINEL INCIDENT INTELLIGENCE ===")

print(f"Risk Score : {intelligence['risk_score']}/100")
print(f"Risk Level : {intelligence['risk_level']}")
print(f"Confidence : {intelligence['confidence'] * 100:.0f}%")

print("\nMITRE")
print(intelligence["mitre"])

print("\nTIMELINE")
for event in intelligence["timeline"]:
    print(
        f"{event['timestamp']} | "
        f"{event['event_type']} | "
        f"{event['source_ip']}"
    )

print("\nNARRATIVE")
print(intelligence["narrative"])