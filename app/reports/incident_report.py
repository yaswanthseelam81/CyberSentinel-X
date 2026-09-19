def generate_report(intelligence: dict) -> str:
    lines = []

    lines.append("=== CYBERSENTINEL INCIDENT REPORT ===")
    lines.append("")

    lines.append(f"Risk Score : {intelligence['risk_score']}/100")
    lines.append(f"Risk Level : {intelligence['risk_level']}")
    lines.append(f"Confidence : {intelligence['confidence'] * 100:.0f}%")

    lines.append("")
    lines.append("MITRE ATT&CK")

    mitre = intelligence.get("mitre")

    if mitre:
        lines.append(
            f"{mitre['technique_id']} - "
            f"{mitre['technique_name']} "
            f"({mitre['tactic']})"
        )
    else:
        lines.append("No MITRE technique mapped.")

    lines.append("")
    lines.append("TIMELINE")

    for event in intelligence["timeline"]:
        lines.append(
            f"{event['timestamp']} | "
            f"{event['event_type']} | "
            f"{event['source_ip']}"
        )

    lines.append("")
    lines.append("ANALYST NARRATIVE")
    lines.append(intelligence["narrative"])

    return "\n".join(lines)