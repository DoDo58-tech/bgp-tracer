"""Report the outage detector's score composition for every scored event.

The quick cache stores an ``outage_score`` that is a weighted sum of feature
indicators.  A single constant score across many different events means the
score carries no information about which class the event belongs to, so the
per-indicator breakdown is what tells us whether the detectors can separate
the classes at all.

The cache is read once and only the small ``outage_analysis`` block is kept.

Usage:
    python3 scripts/outage_score_breakdown.py results/eval_v22/per_event_final.csv
"""
from __future__ import annotations

import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path


def load_cache(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    routing = data.get("routing") or {}
    analysis = routing.get("outage_analysis") or {}
    return analysis if isinstance(analysis, dict) else {}


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2

    rows = list(csv.DictReader(open(sys.argv[1], encoding="utf-8-sig")))
    per_class_scores: dict[str, list[float]] = defaultdict(list)
    indicator_classes: dict[str, Counter] = defaultdict(Counter)
    score_histogram: Counter = Counter()

    for row in rows:
        cache_file = row.get("cache_file")
        if not cache_file or not Path(cache_file).exists():
            continue
        analysis = load_cache(Path(cache_file))
        score = analysis.get("outage_score")
        if not isinstance(score, (int, float)):
            continue
        cause = row.get("gt_cause") or "?"
        per_class_scores[cause].append(float(score))
        score_histogram[round(float(score), 3)] += 1
        for name, detail in (analysis.get("feature_scores") or {}).items():
            if isinstance(detail, dict) and detail.get("triggered"):
                indicator_classes[name][cause] += 1

    print("=== outage_score per class ===")
    for cause, scores in sorted(per_class_scores.items()):
        scores.sort()
        median = scores[len(scores) // 2]
        print(f"  {cause:22s} n={len(scores):2d} "
              f"min={scores[0]:.2f} median={median:.2f} max={scores[-1]:.2f} "
              f"distinct={len(set(round(s, 3) for s in scores))}")

    print("\n=== score histogram ===")
    for score, n in sorted(score_histogram.items()):
        print(f"  {score:6.3f}  {n:3d}")

    print("\n=== triggered indicators per class ===")
    for name, counts in sorted(indicator_classes.items()):
        total = sum(counts.values())
        classes = "  ".join(f"{c}={n}" for c, n in sorted(counts.items()))
        print(f"  {name:24s} total={total:3d}   {classes}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
