"""Produce a real-cache-only subset CSV for paper §6.

Synthetic-cache events are flagged in the cache_source field (any path
starting with 'synthetic' or containing the word 'synthetic'). On the
v11 ground-truth, 7 of 18 evaluable events use synthetic timelines
because either the original quick cache was never generated (BGPStream
events have no fresh RRC00 data) or the analysis window is outside the
Cloudflare Radar 30-day retention.

For reviewers who care about the real-cache-only subset, this script
emits results/eval/per_event_v11_real.csv with the same schema as
per_event_v11.csv and prints the per-method summary on the subset.
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "results" / "eval" / "per_event_v36.csv"
OUT = ROOT / "results" / "eval" / "per_event_v36_real.csv"


def main() -> None:
    with SRC.open() as f:
        rows = list(csv.DictReader(f))
    real = [r for r in rows if "synthetic" not in r["cache_source"]]
    if not real:
        print("FATAL: no real-cache events found", file=sys.stderr)
        sys.exit(1)
    fieldnames = list(real[0].keys())
    with OUT.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(real)

    print(f"Real-cache subset: {len(real)} / {len(rows)} events → {OUT.relative_to(ROOT)}")
    print()
    print(f"{'Method':<20} {'review%':>8} {'strict%':>8} {'abstain%':>9}")
    print("-" * 48)
    methods = ["hcaf", "css", "pearson", "granger", "ts_distance", "transfer_entropy"]
    n = len(real)
    for m in methods:
        rev = sum(int(r[f"{m}_review"]) for r in real) / n * 100
        strict = sum(int(r[f"{m}_strict"]) for r in real) / n * 100
        abst = sum(int(r[f"{m}_abstain"]) for r in real) / n * 100
        print(f"{m:<20} {rev:>8.1f} {strict:>8.1f} {abst:>9.1f}")
    print()
    print("Excluded (synthetic-cache) events:")
    for r in rows:
        if "synthetic" in r["cache_source"]:
            print(f"  - {r['event_id']}  [{r['cause_label']}]")


if __name__ == "__main__":
    main()
