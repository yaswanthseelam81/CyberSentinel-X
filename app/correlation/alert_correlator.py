from collections import defaultdict


def correlate_alerts(alerts: list[dict]) -> list[list[dict]]:
    groups = defaultdict(list)

    for alert in alerts:
        source_ip = alert.get("source_ip")

        if source_ip:
            groups[source_ip].append(alert)

    return list(groups.values())