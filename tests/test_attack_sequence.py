from app.collectors.log_reader import read_log_file
from app.normalizer.log_parser import parse_log_line
from app.detection.attack_sequence import detect_login_compromise_sequence


logs = read_log_file("data/security.log")
events = [parse_log_line(log) for log in logs]

result = detect_login_compromise_sequence(events)

print(result)