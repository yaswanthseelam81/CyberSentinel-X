import json
from pathlib import Path


def load_all_rules(rules_directory: str) -> list[dict]:
    rules = []

    for file in Path(rules_directory).glob("*.json"):
        with file.open("r", encoding="utf-8") as f:
            rules.append(json.load(f))

    return rules