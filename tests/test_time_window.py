from app.collectors.log_reader import read_log_file
from app.normalizer.log_parser import parse_log_line
from app.detection.time_window import events_within_window


logs = read_log_file("data/security.log")

events = [parse_log_line(log) for log in logs]

groups = events_within_window(events, 5)

for number, group in enumerate(groups, start=1):
    print(f"\nGroup {number}")

    for event in group:
        print(event)