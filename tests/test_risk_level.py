from app.risk.risk_level import get_risk_level


scores = [10, 45, 70, 95]

for score in scores:
    print(f"{score}/100 -> {get_risk_level(score)}")