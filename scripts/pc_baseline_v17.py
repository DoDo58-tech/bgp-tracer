#!/usr/bin/env python3
"""Run real PC baseline on the v17 ground truth.

Uses the pc_conditional_independence_baseline from agents/causal_baselines.py
on the real v17 cache files where traffic data is available.
"""
import json
import os
import sys
from pathlib import Path
import numpy as np

ROOT = Path("/data/bgp_tracer")
sys.path.insert(0, str(ROOT))
from agents.causal_baselines import pc_conditional_independence_baseline, BASELINES

OUT = ROOT / "results" / "eval" / "pc_baseline_v17.jsonl"
os.makedirs(OUT.parent, exist_ok=True)

# For each v17 event, find the matching cache
v17 = list((ROOT / "data_check" / "ground_truth_collection" / "final_balanced_dataset_v17_30.csv").open())
# skip header
v17 = v17[1:]

# Load each event's routing + traffic timeline from cache
# We'll use the quick cache files: results/quick/quick_AS<n>_<start>_<end>.json
QUICK_DIR = ROOT / "results" / "quick"

# Map: victim_as → list of cache files
caches_by_as = {}
for f in QUICK_DIR.glob("quick_*.json"):
    name = f.stem  # quick_AS<as>_<start>_<end>
    parts = name.split("_")
    if len(parts) >= 2:
        as_str = parts[1]
        if as_str.startswith("AS"):
            as_str = as_str[2:]
        try:
            as_n = int(as_str)
            caches_by_as.setdefault(as_n, []).append(f)
        except ValueError:
            continue

print(f"Found {len(caches_by_as)} ASes with caches")

# Run PC on each v17 event
results = []
for line in v17:
    parts = line.strip().split(",")
    if len(parts) < 7:
        continue
    event_id = parts[0]
    name = parts[1]
    as_str = parts[6].strip()
    if as_str.startswith("AS"):
        as_str = as_str[2:]
    try:
        victim_as = int(as_str)
    except ValueError:
        continue
    if victim_as is None:
        continue
    caches = caches_by_as.get(victim_as, [])
    if not caches:
        results.append({"event_id": event_id, "victim_as": victim_as,
                        "pc_dir": "no_cache", "pc_conf": 0.0})
        continue
    # Try each cache file
    best_dir = "unknown"
    best_conf = 0.0
    best_lag = 0
    best_partial = 0.0
    for cf in caches[:2]:  # limit per event for speed
        try:
            cache = json.load(open(cf))
        except Exception:
            continue
        # Extract timeline
        timeline = cache.get("correlation", {}).get("timeline", [])
        if not timeline:
            continue
        routing_tl = [t for t in timeline if t.get("source") == "routing"]
        traffic_tl = [t for t in timeline if t.get("source") == "traffic"]
        if len(routing_tl) < 5 or len(traffic_tl) < 5:
            continue
        res = pc_conditional_independence_baseline(routing_tl, traffic_tl)
        if res.confidence > best_conf:
            best_conf = res.confidence
            best_dir = res.direction
            best_lag = res.details.get("best_lag", 0)
            best_partial = res.details.get("best_partial", 0)
    results.append({"event_id": event_id, "victim_as": victim_as,
                    "pc_dir": best_dir, "pc_conf": best_conf,
                    "best_lag": best_lag, "best_partial": best_partial})

# Write JSONL
with open(OUT, "w") as f:
    for r in results:
        f.write(json.dumps(r) + "\n")

# Summary
n_total = len(results)
n_dir = sum(1 for r in results if r["pc_dir"] in ("routing_to_traffic", "traffic_to_routing"))
n_r2t = sum(1 for r in results if r["pc_dir"] == "routing_to_traffic")
n_t2r = sum(1 for r in results if r["pc_dir"] == "traffic_to_routing")
n_unk = sum(1 for r in results if r["pc_dir"] == "unknown")
n_no_cache = sum(1 for r in results if r["pc_dir"] == "no_cache")

print(f"\n=== PC baseline on v17 30 events ===")
print(f"Total: {n_total}")
print(f"No cache: {n_no_cache}")
print(f"Committed direction: {n_dir} ({n_dir/n_total*100:.1f}%)")
print(f"  routing_to_traffic: {n_r2t}")
print(f"  traffic_to_routing: {n_t2r}")
print(f"Abstain (unknown): {n_unk}")
print(f"\nFor events with traffic data (excluding no_cache):")
n_with_data = n_total - n_no_cache
if n_with_data > 0:
    print(f"  Commit rate: {n_dir/n_with_data*100:.1f}%")
