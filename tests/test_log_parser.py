from app.collectors.log_reader import read_log_file
from app.normalizer.log_parser import parse_log_line


logs = read_log_file("data/security.log")

for log in logs:
    event = parse_log_line(log)
    print(event)