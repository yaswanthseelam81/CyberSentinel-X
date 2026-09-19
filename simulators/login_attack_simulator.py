from datetime import datetime, timedelta
from pathlib import Path


OUTPUT_FILE = Path("data/simulated_attack.log")


def generate_brute_force_scenario() -> list[str]:
    start = datetime.now()

    logs = []

    for i in range(5):
        timestamp = start + timedelta(seconds=i * 5)

        logs.append(
            f"{timestamp:%Y-%m-%d %H:%M:%S} "
            f"LOGIN_FAILED user=yash "
            f"ip=192.168.1.50 host=kali-lab"
        )

    success_time = start + timedelta(seconds=30)

    logs.append(
        f"{success_time:%Y-%m-%d %H:%M:%S} "
        f"LOGIN_SUCCESS user=yash "
        f"ip=192.168.1.50 host=kali-lab"
    )

    return logs


def save_logs(logs: list[str]) -> None:
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    OUTPUT_FILE.write_text(
        "\n".join(logs),
        encoding="utf-8",
    )


if __name__ == "__main__":
    logs = generate_brute_force_scenario()
    save_logs(logs)

    print(f"Saved {len(logs)} events to {OUTPUT_FILE}")