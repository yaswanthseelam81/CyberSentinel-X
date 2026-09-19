from app.investigation.case_status import update_status


case = {
    "case_id": "CASE-0001",
    "status": "OPEN",
}

for status in ["INVESTIGATING", "CONTAINED", "RESOLVED"]:
    case = update_status(case, status)
    print(f"{case['case_id']} -> {case['status']}")