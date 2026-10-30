#!/usr/bin/env python3
"""Quantify the temporal mismatch in the leak detector's path model.

The valley-free + path-probability leak detector is scored against a
single CAIDA AS-relationship snapshot.  Events outside that snapshot's
period are therefore scored against an AS topology that did not hold at
the time of the event, which is a source of false positives.

This script groups the cached events by the ground-truth year and reports,
per year, how many distinct leaking routes the detector reports and how
many of those the ground truth attributes to a leak.  A detector whose
false-positive rate is flat across years is not being hurt by the
mismatch; a detector whose rate falls outside the snapshot period is.

Writes results/eval/leak_temporal_mismatch.json.
"""

from __future__ import annotations

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.cache_resolution import resolve_cache  # noqa: E402

QUICK_DIR = PROJECT_ROOT / "results" / "quick"
GT_CSV = PROJECT_ROOT / "data_check" / "ground_truth_collection" / "final_ground_truth.csv"
OUT_PATH = PROJECT_ROOT / "results" / "eval" / "leak_temporal_mismatch.json"

# The path-probability model that the detector loads (single available period).
SNAPSHOT_YEAR = 2025


def signature(entry: dict) -> tuple | None:
    prefixes = entry.get("affected_prefixes") or []
    if isinstance(prefixes, list) and prefixes:
        prefix = tuple(sorted(str(p) for p in prefixes))
    else:
        prefix = str(entry.get("prefix") or "")
    evidence = entry.get("evidence") or {}
    path = ""
    if isinstance(evidence, dict):
        path = str(evidence.get("as_path") or evidence.get("as-path") or "")
    claimed = str(entry.get("claimed_as") or "")
    if not prefix and not path:
        return None
    return (prefix, path, claimed)


def main() -> int:
    rows = list(csv.DictReader(GT_CSV.open()))
    per_year: dict[int, dict] = defaultdict(
        lambda: {"n_events": 0, "n_leak_gt": 0, "n_leak_gt_with_any_leak": 0,
                 "distinct_leaks": []}
    )

    for row in rows:
        event_id = row["event_id"]
        cause = row["cause"]
        asn = str(row["victim_as"]).replace("AS", "").strip()
        year = int(str(row["start_utc"])[:4])
        match = resolve_cache(asn, row["start_utc"], row["end_utc"], QUICK_DIR,
                              event_id=event_id, allow_same_date=True)
        if match is None:
            continue
        cache = json.loads(match.path.read_text())
        routing = cache.get("routing") or {}
        sigs = set()
        for leak in routing.get("route_leaks") or []:
            if not isinstance(leak, dict):
                continue
            sig = signature(leak)
            if sig is not None:
                sigs.add(sig)
        bucket = per_year[year]
        bucket["n_events"] += 1
        bucket["distinct_leaks"].append(len(sigs))
        if cause == "route_leak":
            bucket["n_leak_gt"] += 1
            if sigs:
                bucket["n_leak_gt_with_any_leak"] += 1

    report = {}
    for year, bucket in sorted(per_year.items()):
        counts = bucket["distinct_leaks"]
        report[str(year)] = {
            "n_events": bucket["n_events"],
            "n_leak_gt": bucket["n_leak_gt"],
            "leak_gt_recall": (
                bucket["n_leak_gt_with_any_leak"] / bucket["n_leak_gt"]
                if bucket["n_leak_gt"] else None
            ),
            "median_distinct_leaks": sorted(counts)[len(counts) // 2] if counts else 0,
            "mean_distinct_leaks": sum(counts) / len(counts) if counts else 0.0,
            "in_snapshot_year": year == SNAPSHOT_YEAR,
        }

    payload = {
        "path_probability_snapshot_year": SNAPSHOT_YEAR,
        "note": (
            "The leak detector scores every event against one AS-relationship "
            "snapshot.  Events outside the snapshot year are scored against a "
            "topology that did not hold at the event time."
        ),
        "per_year": report,
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(payload, indent=2) + "\n")

    print(f"leak temporal mismatch (snapshot year {SNAPSHOT_YEAR})")
    print(f"{'year':>6s} {'events':>7s} {'leakGT':>7s} {'recall':>8s} {'medLeaks':>9s} {'inSnap':>7s}")
    for year, cell in report.items():
        recall = cell["leak_gt_recall"]
        recall_s = f"{recall:.2f}" if recall is not None else "  n/a"
        print(f"{year:>6s} {cell['n_events']:>7d} {cell['n_leak_gt']:>7d} "
              f"{recall_s:>8s} {cell['median_distinct_leaks']:>9d} "
              f"{str(cell['in_snapshot_year']):>7s}")
    print(f"\nwrote {OUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
