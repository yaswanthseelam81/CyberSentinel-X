from datetime import datetime
from pathlib import Path


OUTPUT_FILE = Path("data/suspicious_dns.log")


def generate_scenario() -> list[str]:
    timestamp = datetime.now()

    return [
        (
            f"{timestamp:%Y-%m-%d %H:%M:%S} "
            f"DNS_QUERY user=yash "
            f"ip=192.168.1.60 host=kali-lab "
            f"domain=very-long-suspicious-domain.example"
        )
    ]


if __name__ == "__main__":
    logs = generate_scenario()

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text("\n".join(logs), encoding="utf-8")

    print(f"Saved {len(logs)} events to {OUTPUT_FILE}")