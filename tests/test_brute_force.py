from app.collectors.log_reader import read_log_file
from app.normalizer.log_parser import parse_log_line
from app.detection.brute_force import detect_brute_force


logs = read_log_file("data/security.log")

events = [parse_log_line(log) for log in logs]

alerts = detect_brute_force(events)

print(alerts)