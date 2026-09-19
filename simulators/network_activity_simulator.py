from datetime import datetime
from pathlib import Path


OUTPUT_FILE = Path("data/unusual_network.log")


def generate_scenario() -> list[str]:
    timestamp = datetime.now()

    return [
        (
            f"{timestamp:%Y-%m-%d %H:%M:%S} "
            f"NETWORK_CONNECTION user=yash "
            f"ip=192.168.1.60 host=kali-lab "
            f"destination=203.0.113.50"
        )
    ]


if __name__ == "__main__":
    logs = generate_scenario()

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text("\n".join(logs), encoding="utf-8")

    print(f"Saved {len(logs)} events to {OUTPUT_FILE}")