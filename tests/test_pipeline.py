from app.pipeline import run_pipeline


result = run_pipeline("data/simulated_attack.log")

print("\n=== CYBERSENTINEL PIPELINE ===")

print(f"Events detected : {result.event_count}")
print(f"Alerts generated: {result.alert_count}")
print(f"Incidents       : {result.incident_count}")

for incident in result.incidents:
    print("\nINCIDENT")
    print(f"ID       : {incident['incident_id']}")
    print(f"Source   : {incident['source_ip']}")
    print(f"Alerts   : {incident['alert_count']}")
    print(f"Severity : {incident['severity']}")
    print(f"Status   : {incident['status']}")