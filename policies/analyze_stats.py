import json
import sys

def load(fname):
    try:
        with open(fname) as f:
            return {p["id"]: p for p in json.load(f) if "tinylfu" in p.get("name", "")}
    except FileNotFoundError:
        print(f"Error: {fname} not found.")
        return {}

start = load("bpf_stats_start.json")
end = load("bpf_stats_end.json")

print(f"{'INFO': <30} | {'RUNS': <10} | {'TOTAL_NS': <15} | {'AVG_NS': <10}")
print("-" * 75)

for pid, p_end in end.items():
    if pid not in start:
        continue
    p_start = start[pid]
    
    run_cnt = p_end.get("run_cnt", 0) - p_start.get("run_cnt", 0)
    run_time = p_end.get("run_time_ns", 0) - p_start.get("run_time_ns", 0)
    
    if run_cnt > 0:
        avg = run_time / run_cnt
        name = p_end.get("name", f"prog_{pid}")
        print(f"{name: <30} | {run_cnt: <10} | {run_time: <15} | {avg: .0f}")
