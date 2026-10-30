#!/usr/bin/env python3
"""Origin-mismatch test for route leaks.

The path-probability detector answers "is this AS-path unusual for the
AS that announced it?".  That question does not distinguish a leak from a
withdrawal storm: during an outage the AS announces a small, perturbed set
of paths through unfamiliar peers, and those paths also look unusual.

A route leak has a sharper signature.  The leaking AS announces prefixes
whose legitimate origin belongs to a *different* AS, and it announces them
to peers that are not its customers.  The legitimate origin is known
independently of the announcement: it comes from the RouteViews prefix-to-AS
snapshot for the event's date.

This module re-scores the cached leak records with that test:

  * `origin_mismatch` — the announced prefix's legitimate origin (from the
    snapshot) is not the announcing AS.  These are genuine leaks.
  * `announced_by_self` — the prefix legitimately belongs to the announcing
    AS, so the path is unusual but the prefix is not stolen.

Only the first kind is a leak in the sense the ground truth uses.  The
script reports, per ground-truth class, how many distinct prefixes fall
into each kind.

Writes results/eval/leak_origin_mismatch.json.
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
from data.prefix2as_loader import load_prefix2as_json  # noqa: E402

QUICK_DIR = PROJECT_ROOT / "results" / "quick"
GT_CSV = PROJECT_ROOT / "data_check" / "ground_truth_collection" / "final_ground_truth.csv"
OUT_PATH = PROJECT_ROOT / "results" / "eval" / "leak_origin_mismatch.json"
CLASSES = ("outage", "route_leak", "origin_hijack_victim")


def prefix_owner_map(target_time: str) -> dict:
    """Load the prefix-to-AS snapshot closest to the event date."""
    from data.prefix2as_loader import process_prefix2as
    from datetime import datetime

    stamp = datetime.fromisoformat(target_time)
    path = process_prefix2as(stamp)
    data = load_prefix2as_json(path)
    return data or {}


def main() -> int:
    rows = list(csv.DictReader(GT_CSV.open()))
    per_event = {}
    totals = defaultdict(lambda: {
        "n_events": 0,
        "n_with_snapshot": 0,
        "origin_mismatch_prefixes": 0,
        "announced_by_self_prefixes": 0,
        "unknown_prefixes": 0,
    })

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
        leaks = routing.get("route_leaks") or []
        if not leaks:
            continue

        owners = prefix_owner_map(row["start_utc"])
        bucket = totals[cause]
        bucket["n_events"] += 1
        if owners:
            bucket["n_with_snapshot"] += 1

        mismatch: set[str] = set()
        by_self: set[str] = set()
        unknown: set[str] = set()
        for leak in leaks:
            if not isinstance(leak, dict):
                continue
            for prefix in leak.get("affected_prefixes") or []:
                prefix = str(prefix)
                legit = owners.get(prefix)
                if not legit:
                    unknown.add(prefix)
                elif asn in [str(x) for x in legit]:
                    by_self.add(prefix)
                else:
                    mismatch.add(prefix)

        bucket["origin_mismatch_prefixes"] += len(mismatch)
        bucket["announced_by_self_prefixes"] += len(by_self)
        bucket["unknown_prefixes"] += len(unknown)
        per_event[event_id] = {
            "cause": cause,
            "origin_mismatch": len(mismatch),
            "announced_by_self": len(by_self),
            "unknown": len(unknown),
        }

    report = {}
    for cause, bucket in totals.items():
        n = bucket["n_events"]
        report[cause] = {
            **bucket,
            "mean_origin_mismatch": (
                bucket["origin_mismatch_prefixes"] / n if n else 0.0
            ),
            "mean_announced_by_self": (
                bucket["announced_by_self_prefixes"] / n if n else 0.0
            ),
        }

    payload = {
        "dataset": "final_ground_truth.csv",
        "n_events_scored": len(per_event),
        "per_class": report,
        "per_event": per_event,
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(payload, indent=2) + "\n")

    print("leak origin-mismatch test")
    print(f"{'class':22s} {'events':>7s} {'snap':>5s} {'mismatch/ev':>13s} {'self/ev':>9s}")
    for cause in CLASSES:
        cell = report.get(cause)
        if not cell:
            continue
        print(f"{cause:22s} {cell['n_events']:>7d} {cell['n_with_snapshot']:>5d} "
              f"{cell['mean_origin_mismatch']:>13.1f} "
              f"{cell['mean_announced_by_self']:>9.1f}")
    print(f"\nwrote {OUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
