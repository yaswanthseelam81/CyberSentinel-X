from app.collectors.log_reader import read_log_file
from app.normalizer.log_parser import parse_log_line
from app.investigation.evidence import collect_evidence


logs = read_log_file("data/security.log")
events = [parse_log_line(log) for log in logs]

evidence = collect_evidence(events)

for item in evidence:
    print(item)