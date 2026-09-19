from datetime import datetime, timedelta
from pathlib import Path


OUTPUT_FILE = Path("data/privilege_escalation.log")


def generate_scenario() -> list[str]:
    start = datetime.now()

    return [
        (
            f"{start:%Y-%m-%d %H:%M:%S} "
            f"LOGIN_SUCCESS user=yash ip=192.168.1.60 host=kali-lab"
        ),
        (
            f"{(start + timedelta(seconds=10)):%Y-%m-%d %H:%M:%S} "
            f"PRIVILEGE_GRANTED user=yash ip=192.168.1.60 host=kali-lab"
        ),
    ]


if __name__ == "__main__":
    logs = generate_scenario()

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text("\n".join(logs), encoding="utf-8")

    print(f"Saved {len(logs)} events to {OUTPUT_FILE}")