from app.collectors.log_reader import read_log_file
from app.normalizer.log_parser import parse_log_line
from app.investigation.attack_chain_report import (
    generate_attack_chain_report,
)


logs = read_log_file(
    "data/full_attack_chain.log"
)

events = [
    parse_log_line(log)
    for log in logs
]

report = generate_attack_chain_report(
    events
)


print("\n=== EVIDENCE-BACKED ATTACK CHAIN ===")

print(
    f"Detected    : {report['detected']}"
)

print(
    f"Stages      : {report['stage_count']}"
)

print(
    f"Chain Risk  : {report['total_risk']}/100"
)

print(
    f"Confidence  : "
    f"{report['confidence'] * 100:.1f}%"
)


for index, stage in enumerate(
    report["stages"],
    start=1,
):

    print(
        f"\n[{index}] {stage['stage']}"
    )

    print(
        f"Time       : {stage['timestamp']}"
    )

    print(
        f"Event      : {stage['event_type']}"
    )

    print(
        f"MITRE      : "
        f"{stage['mitre_technique']} - "
        f"{stage['mitre_name']}"
    )

    print(
        f"Tactic     : {stage['tactic']}"
    )

    print(
        f"Risk       : +{stage['risk']}"
    )

    print(
        f"Confidence : "
        f"{stage['confidence'] * 100:.0f}%"
    )

    print(
        f"Evidence   : "
        f"{stage['evidence']}"
    )