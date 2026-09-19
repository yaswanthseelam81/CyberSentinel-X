from pathlib import Path


def read_log_file(file_path: str) -> list[str]:
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    with path.open("r", encoding="utf-8") as file:
        return [line.strip() for line in file if line.strip()]