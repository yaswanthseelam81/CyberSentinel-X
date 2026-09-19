from app.collectors.log_reader import read_log_file
from app.normalizer.log_parser import parse_log_line
from app.investigation.timeline import build_timeline


logs = read_log_file("data/security.log")
events = [parse_log_line(log) for log in logs]

timeline = build_timeline(events)

for item in timeline:
    print(item)
    