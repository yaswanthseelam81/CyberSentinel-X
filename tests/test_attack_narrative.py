from app.collectors.log_reader import read_log_file
from app.normalizer.log_parser import parse_log_line
from app.investigation.attack_narrative import generate_attack_narrative


logs = read_log_file("data/security.log")
events = [parse_log_line(log) for log in logs]

narrative = generate_attack_narrative(events)

print("\nATTACK NARRATIVE")
print(narrative)