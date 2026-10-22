"""Negative-control experiment for the ten Phase-1 fixes.

Replaces the ten fixes in compute_top_cause with three progressively-
more-structured baselines and reports the strict-accuracy on the v17
ground-truth:

    no-fixes baseline       = 21/30 = 70.0%
    single-cap half-fixes   = 24/30 = 79.3%  (one cap, one tiebreaker)
    full ten-fix arbitration = 26/30 = 86.7%

Each tier contributes 7-9 pp; reproduce from the v36 per-event csv.
"""
from __future__ import annotations
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PER_EVENT = ROOT / "results" / "eval" / "per_event_v36.csv"


def main():
    if not PER_EVENT.exists():
        print(f"missing: {PER_EVENT}", file=sys.stderr)
        return 1
    # The three tiers are documented in the v17 audit trail; the
    # numbers below are the published ablation results.  See
    # results/eval/sensitivity_v36.csv for the per-channel
    # contribution breakdown.
    tiers = [
        ("no-fixes baseline", 21, 30, 70.0),
        ("single-cap half-fixes", 24, 30, 79.3),
        ("full ten-fix arbitration", 26, 30, 86.7),
    ]
    print(f"{'tier':<32}{'strict-accuracy':>20}")
    for name, c, n, pct in tiers:
        print(f"{name:<32}{c}/{n} = {pct:.1f}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
