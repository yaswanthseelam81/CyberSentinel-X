from datetime import datetime


def build_correlated_incident(alerts: list[dict]) -> dict:
    if not alerts:
        raise ValueError("Cannot build an incident without alerts.")

    source_ip = alerts[0].get(
        "source_ip",
        "UNKNOWN",
    )

    severities = [
        alert.get("severity", "LOW")
        for alert in alerts
    ]

    severity_order = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }

    highest_severity = max(
        severities,
        key=lambda severity: severity_order.get(
            severity,
            0,
        ),
    )

    # Use the earliest alert timestamp so the same
    # attack produces the same incident ID across reruns.
    timestamps = [
        alert.get("timestamp")
        for alert in alerts
        if alert.get("timestamp")
    ]

    if timestamps:
        created_at = min(timestamps)

        try:
            parsed_time = datetime.fromisoformat(
                created_at
            )
            incident_time = parsed_time.strftime(
                "%Y%m%d%H%M%S"
            )
        except ValueError:
            incident_time = "UNKNOWN"
    else:
        created_at = datetime.now().isoformat()
        incident_time = datetime.now().strftime(
            "%Y%m%d%H%M%S"
        )

    safe_ip = source_ip.replace(".", "-")

    incident_id = (
        f"INC-{incident_time}-{safe_ip}"
    )

    return {
        "incident_id": incident_id,
        "source_ip": source_ip,
        "alert_count": len(alerts),
        "severity": highest_severity,
        "status": "OPEN",
        "created_at": created_at,
        "alerts": alerts,
    }