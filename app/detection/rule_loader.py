import json
from pathlib import Path


def load_rule(file_path: str) -> dict:
    path = Path(file_path)

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)