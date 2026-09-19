from app.collectors.log_reader import read_log_file
from app.normalizer.log_parser import parse_log_line
from app.investigation.attack_chain import reconstruct_attack_chain


logs = read_log_file("data/full_attack_chain.log")
events = [parse_log_line(log) for log in logs]

result = reconstruct_attack_chain(events)

print("\n=== ATTACK CHAIN ===")
print(f"Detected: {result['attack_chain_detected']}")
print(f"Stages: {result['stage_count']}")

for stage in result["stages"]:
    print(f"  → {stage}")