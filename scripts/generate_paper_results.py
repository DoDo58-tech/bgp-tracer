#!/usr/bin/env python3
"""Generate a paper-grade results CSV for the mentor review.

Format:
  event_id,ground_truth,predicted,confidence,match,is_negative_control
"""
import csv
import re
import sys
import json
from pathlib import Path
from datetime import datetime

sys.path.insert(0, "scripts")
from cache_only_evaluation_v17 import _find_quick, _resolve_target_as
import importlib
import agents.report_agent as ra
importlib.reload(ra)
from agents.report_agent import compute_top_cause, _normalize_routing, _normalize_traffic

CSV_PATH = Path("data_check/ground_truth_collection/final_balanced_dataset_v17.csv")
QUICK_DIR = Path("results/quick")
OUT_CSV = Path("logs/paper_grade_results.csv")

# Map: cause → human label
CAUSE_LABELS = {
    "outage": "BGP Reachability Outage",
    "route_leak": "Route Leak",
    "origin_hijack_victim": "Origin Hijack (AS is victim)",
    "origin_hijack_attacker": "Origin Hijack (AS is attacker)",
    "roa_misconfig": "ROA Misconfiguration (RPKI/IRR gap)",
    "traffic_anomaly_only": "Traffic anomaly, routing quiet",
    "no_clear_anomaly": "No clear anomaly",
    "independent_coincidence": "Independent coincidence",
}

def main():
    rows = []
    n_total = 0
    n_correct = 0
    n_excl_total = 0
    n_excl_correct = 0
    n_pred = 0

    with open(CSV_PATH) as f:
        events = list(csv.DictReader(f))

    for row in events:
        ev_id = row["event_id"]
        gt = (row.get("ground_truth_cause_label") or "").strip().lower()
        is_neg = (row.get("ground_truth_root_cause_subtype") or "").strip().lower() == "internal_failure_non_bgp"
        target_as = _resolve_target_as(row)
        cache = _find_quick(ev_id, target_as) if target_as else None
        if not cache:
            rows.append({
                "event_id": ev_id,
                "ground_truth": gt,
                "predicted": "MISSING_CACHE",
                "confidence": 0.0,
                "match": False,
                "is_negative_control": is_neg,
                "cache_path": "",
            })
            n_total += 1
            if not is_neg:
                n_excl_total += 1
            continue
        try:
            data = json.loads(cache.read_text())
        except Exception as e:
            rows.append({
                "event_id": ev_id,
                "ground_truth": gt,
                "predicted": f"PARSE_ERROR:{e}",
                "confidence": 0.0,
                "match": False,
                "is_negative_control": is_neg,
                "cache_path": str(cache),
            })
            n_total += 1
            if not is_neg:
                n_excl_total += 1
            continue

        rout = data.get("routing", {})
        traffic = data.get("traffic", {})
        corr = data.get("correlation", {})
        routing_norm = _normalize_routing(rout)
        traffic_norm = _normalize_traffic(traffic)
        correlation_norm = {
            "temporal_proximity": corr.get("summary", {}).get("correlation_level", "none"),
            "confidence": corr.get("summary", {}).get("correlation_confidence", 0.0),
        }
        hcaf = routing_norm.get("hcaf_direction", "") or ""
        if hcaf not in ("traffic_to_routing", "routing_to_traffic"):
            hcaf = ""
        top = compute_top_cause(
            routing_norm=routing_norm,
            traffic_norm=traffic_norm,
            correlation_norm=correlation_norm,
            target_as=target_as,
            hcaf_direction=hcaf,
        )
        pred_cause = top["cause"]
        conf = top["confidence"]
        # Match logic: same cause for non-neg, any non-outage for neg
        if is_neg:
            match = pred_cause != "outage"
        else:
            match = pred_cause == gt
        rows.append({
            "event_id": ev_id,
            "ground_truth": gt,
            "predicted": pred_cause,
            "confidence": conf,
            "match": match,
            "is_negative_control": is_neg,
            "cache_path": str(cache),
        })
        n_total += 1
        n_pred += 1
        if match:
            n_correct += 1
        if not is_neg:
            n_excl_total += 1
            if match:
                n_excl_correct += 1

    # Write CSV
    with open(OUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["event_id", "ground_truth", "predicted", "confidence", "match", "is_negative_control", "cache_path"])
        w.writeheader()
        w.writerows(rows)

    # Print summary
    print(f"Total events: {n_total}")
    print(f"Predictions: {n_pred}")
    print(f"Correct: {n_correct}")
    print()
    print(f"Excluding negative control: {n_excl_total} events, {n_excl_correct} correct = {n_excl_correct/n_excl_total*100:.1f}%")
    print()
    print(f"Cached results written to {OUT_CSV}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
