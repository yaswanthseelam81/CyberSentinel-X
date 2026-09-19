from dataclasses import dataclass


@dataclass
class ScenarioResult:
    name: str
    expected: bool
    detected: bool

    @property
    def passed(self) -> bool:
        return self.expected == self.detected


def calculate_metrics(
    results: list[ScenarioResult],
) -> dict:
    if not results:
        return {
            "total": 0,
            "passed": 0,
            "failed": 0,
            "detection_rate": 0.0,
        }

    passed = sum(result.passed for result in results)
    total = len(results)

    return {
        "total": total,
        "passed": passed,
        "failed": total - passed,
        "detection_rate": (passed / total) * 100,
    }