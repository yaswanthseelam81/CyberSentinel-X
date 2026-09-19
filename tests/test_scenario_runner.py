from app.evaluation.scenario_runner import run_all_scenarios


results = run_all_scenarios()

print("\n=== AUTOMATED SCENARIO EVALUATION ===")

for result in results:
    status = "PASS" if result["detected"] else "FAIL"

    print(
        f"{result['scenario']:<22} "
        f"Events: {result['events']:<2} "
        f"Alerts: {result['alerts']:<2} "
        f"{status}"
    )