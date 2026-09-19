from app.alert_builder import build_brute_force_alert


alert = build_brute_force_alert(
    source_ip="192.168.1.50",
    username="yash",
    host="kali-lab",
    failed_attempts=5,
    window_minutes=5,
    risk_score=98,
)

print(alert)