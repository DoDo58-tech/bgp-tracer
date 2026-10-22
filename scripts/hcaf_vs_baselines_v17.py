#!/usr/bin/env python3
"""Run all real causal baselines on v17 events for the paper.

Compares HCAF, Pearson, Granger, Timestamp, Transfer Entropy, and PC
on the v17 30-event ground-truth (using real caches).
"""
import json
import os
import sys
from pathlib import Path
import numpy as np
from collections import defaultdict, Counter

ROOT = Path("/data/bgp_tracer")
sys.path.insert(0, str(ROOT))
from agents.causal_baselines import (
    BASELINES, pearson_baseline, granger_baseline,
    timestamp_distance_baseline, transfer_entropy_baseline,
    pc_conditional_independence_baseline,
)

OUT = ROOT / "results" / "eval" / "hcaf_vs_baselines_v17.csv"
os.makedirs(OUT.parent, exist_ok=True)

# Load v17 ground truth
v17 = []
with open(ROOT / "data_check" / "ground_truth_collection" / "final_balanced_dataset_v17_30.csv") as f:
    header = f.readline().strip().split(",")
    for line in f:
        parts = line.strip().split(",")
        if len(parts) < 7: continue
        v17.append(dict(zip(header, parts)))

# Group caches by AS
QUICK_DIR = ROOT / "results" / "quick"
caches_by_as = defaultdict(list)
for cf in QUICK_DIR.glob("quick_*.json"):
    name = cf.stem  # e.g. quick_22773_2024-10-30T1321_2024-10-30T1340
    # AS is the first number segment after "quick_"
    if not name.startswith("quick_"):
        continue
    remainder = name[6:]  # 22773_2024-10-30T1321_2024-10-30T1340
    as_str = ""
    for ch in remainder:
        if ch.isdigit():
            as_str += ch
        else:
            break
    try:
        as_n = int(as_str)
        caches_by_as[as_n].append(cf)
    except ValueError:
        continue

# For each event, run each baseline
results = []
for ev in v17:
    as_str = ev["victim_as"].lstrip("AS")
    try:
        as_n = int(as_str)
    except ValueError:
        continue
    caches = caches_by_as.get(as_n, [])
    if not caches:
        for m in ["hcaf", "pearson", "granger", "timestamp_distance",
                  "transfer_entropy", "pc_conditional_independence"]:
            results.append({"event_id": ev["event_id"], "method": m, "dir": "no_cache", "conf": 0})
        continue
    # Try each cache, take the best-confidence result
    best_per_method = {m: None for m in ["pearson", "granger", "timestamp_distance",
                                          "transfer_entropy", "pc_conditional_independence"]}
    for cf in caches[:1]:  # one cache per event for speed
        try:
            cache = json.load(open(cf))
        except Exception:
            continue
        timeline = cache.get("correlation", {}).get("timeline", [])
        if not timeline:
            continue
        r_tl = [t for t in timeline if t.get("source") == "routing"]
        t_tl = [t for t in timeline if t.get("source") == "traffic"]
        if len(r_tl) < 5 or len(t_tl) < 5:
            continue
        for m in best_per_method.keys():
            res = BASELINES[m](r_tl, t_tl)
            cur = best_per_method[m]
            if cur is None or res.confidence > cur.confidence:
                best_per_method[m] = res
    for m, res in best_per_method.items():
        if res is None:
            results.append({"event_id": ev["event_id"], "method": m, "dir": "no_cache", "conf": 0})
        else:
            results.append({"event_id": ev["event_id"], "method": m,
                            "dir": res.direction, "conf": res.confidence})

# Summarise
import csv
with open(OUT, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["event_id", "method", "dir", "conf"])
    w.writeheader()
    for r in results:
        w.writerow(r)

# Print summary
methods = ["pearson", "granger", "timestamp_distance", "transfer_entropy",
           "pc_conditional_independence"]
print(f"\n=== Real baseline results on v17 (n_events={len(v17)}) ===")
print(f"{'Method':<30s} {'Commit':<10s} {'%':<6s} {'R→T':<6s} {'T→R':<6s} {'Unk':<6s}")
for m in methods:
    mres = [r for r in results if r["method"] == m]
    n_total = len(mres)
    n_dir = sum(1 for r in mres if r["dir"] in ("routing_to_traffic", "traffic_to_routing"))
    n_r2t = sum(1 for r in mres if r["dir"] == "routing_to_traffic")
    n_t2r = sum(1 for r in mres if r["dir"] == "traffic_to_routing")
    n_unk = sum(1 for r in mres if r["dir"] == "unknown")
    pct = n_dir / n_total * 100 if n_total else 0
    print(f"{m:<30s} {n_dir:<10d} {pct:<6.1f} {n_r2t:<6d} {n_t2r:<6d} {n_unk:<6d}")
