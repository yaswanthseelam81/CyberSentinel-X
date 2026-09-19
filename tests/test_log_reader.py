from app.collectors.log_reader import read_log_file


logs = read_log_file("data/security.log")

for log in logs:
    print(log)