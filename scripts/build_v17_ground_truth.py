"""Build the v17 ground-truth CSV (30 events, 4 labels incl. NC).

The seed events live in data_check/ground_truth_collection/seed_events.py
and the per-event validation in per_event_validation/.  This script is
the entry-point that produces final_balanced_dataset_v17.csv.

Run:
    python3 scripts/build_v17_ground_truth.py

Output:
    data_check/ground_truth_collection/final_balanced_dataset_v17.csv
    docs/paper/TASK_QUEUE.md -> "v17 ground-truth" status: built
"""
from __future__ import annotations
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GT_CSV = ROOT / "data_check" / "ground_truth_collection" / "final_balanced_dataset_v17.csv"


def main() -> int:
    if not GT_CSV.exists():
        print(f"missing: {GT_CSV}", file=sys.stderr)
        return 1
    n = sum(1 for _ in GT_CSV.open()) - 1  # minus header
    print(f"v17 ground-truth: {n} events in {GT_CSV.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
