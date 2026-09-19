from app.collectors.log_reader import read_log_file
from app.normalizer.log_parser import parse_log_line
from app.risk.risk_engine import calculate_risk


logs = read_log_file("data/security.log")
events = [parse_log_line(log) for log in logs]

risk = calculate_risk(events, confidence=0.95)

print(f"Risk Score: {risk}/100")