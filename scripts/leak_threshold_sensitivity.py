#!/usr/bin/env python3
"""Measure how the leak detector's probability threshold separates leaks.

The detector emits a leak record per announcement whose PathProb falls
below `DEFAULT_LEAK_THRESHOLD`.  The threshold is a free parameter, so
its effect on class separability has to be measured rather than assumed.

For every cached event this script bins the recorded leak probabilities
and reports, per ground-truth class, how many *distinct leaking routes*
fall below each candidate threshold.  A threshold that separates leaks
from outages and hijacks shows a clear ordering of the per-class medians
with little overlap; a threshold that does not separate them shows curves
that lie on top of each other.

Writes results/eval/leak_threshold_sensitivity.json.
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
OUT_PATH = PROJECT_ROOT / "results" / "eval" / "leak_threshold_sensitivity.json"

THRESHOLDS = (0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.35, 0.40)
CLASSES = ("outage", "route_leak", "origin_hijack_victim")


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
    # event_id -> list of (probability, signature)
    per_event: dict[str, list[tuple[float, tuple]]] = {}

    for row in rows:
        event_id = row["event_id"]
        cause = row["cause"]
        if cause not in CLASSES:
            continue
        asn = str(row["victim_as"]).replace("AS", "").strip()
        match = resolve_cache(asn, row["start_utc"], row["end_utc"], QUICK_DIR,
                              event_id=event_id, allow_same_date=True)
        if match is None:
            continue
        cache = json.loads(match.path.read_text())
        routing = cache.get("routing") or {}
        entries = []
        for leak in routing.get("route_leaks") or []:
            if not isinstance(leak, dict):
                continue
            evidence = leak.get("evidence") or {}
            prob = evidence.get("leak_probability")
            if prob is None:
                continue
            sig = signature(leak)
            if sig is None:
                continue
            entries.append((float(prob), sig))
        if entries:
            per_event[event_id] = (cause, entries)

    report = {}
    for threshold in THRESHOLDS:
        counts: dict[str, list[int]] = defaultdict(list)
        for cause, entries in per_event.values():
            selected = {sig for prob, sig in entries if prob < threshold}
            counts[cause].append(len(selected))
        report[f"{threshold:.2f}"] = {
            cause: {
                "n_events": len(counts[cause]),
                "median_distinct_leaks": (
                    sorted(counts[cause])[len(counts[cause]) // 2]
                    if counts[cause] else 0
                ),
                "mean_distinct_leaks": (
                    sum(counts[cause]) / len(counts[cause]) if counts[cause] else 0.0
                ),
            }
            for cause in CLASSES
        }

    payload = {
        "dataset": "final_ground_truth.csv",
        "n_events_scored": len(per_event),
        "current_threshold": 0.40,
        "thresholds": report,
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(payload, indent=2) + "\n")

    print(f"leak threshold sensitivity over {len(per_event)} cached events")
    print(f"{'thr':>5s} | " + " | ".join(f"{c:>22s}" for c in CLASSES))
    for threshold in THRESHOLDS:
        key = f"{threshold:.2f}"
        cells = []
        for cause in CLASSES:
            cell = report[key][cause]
            cells.append(f"med={cell['median_distinct_leaks']:>5d}")
        print(f"{key:>5s} | " + " | ".join(cells))
    print(f"\nwrote {OUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
