"""Floor sensitivity sweep for HCAF composite (paper §6.7.5).

Re-runs the HCAF synthesis at confidence floors
{c: 0.10, 0.30, 0.55, 0.80} on the released JSONL
and reports the strict-precision / review-precision
trade-off at each floor.

The output is `results/eval/floor_sensitivity.csv`,
which the paper cites as the empirical evidence for
the dependability-favouring floor choice.
"""
from __future__ import annotations
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
JSONL = ROOT / "results" / "eval" / "hcaf_vs_baselines_30.jsonl"
OUT_CSV = ROOT / "results" / "eval" / "floor_sensitivity.csv"


def main() -> int:
    if not JSONL.exists():
        print(f"missing: {JSONL}", file=sys.stderr)
        return 1

    records = []
    with JSONL.open() as f:
        for line in f:
            records.append(json.loads(line))

    # The HCAF composite's "committed" status is determined by
    # hcaf_confidence, not by the raw posterior max. The HCAF
    # floor c is the minimum hcaf_confidence required to commit
    # a direction. The hcaf_direction field is "unknown" when
    # the composite abstains.
    rows = []
    for c in (0.10, 0.30, 0.55, 0.80):
        committed = [r for r in records if r.get("hcaf_direction") not in (None, "unknown") and (r.get("hcaf_confidence") or 0) >= c]
        correct = sum(1 for r in committed if r.get("hcaf_direction") == r.get("expected_direction"))
        abst = len(records) - len(committed)
        strict_pct = (correct / len(records)) * 100 if records else 0.0
        review_pct = ((correct + abst) / len(records)) * 100 if records else 0.0
        rows.append({
            "floor": c,
            "commits": len(committed),
            "abstains": abst,
            "strict_correct": correct,
            "strict_precision_pct": round(strict_pct, 1),
            "review_precision_pct": round(review_pct, 1),
        })

    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with OUT_CSV.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    print(f"{'floor':<10}{'commits':>10}{'abst':>8}"
          f"{'strict-prec':>14}{'review-prec':>14}")
    for r in rows:
        print(f"{r['floor']:<10}{r['commits']:>10}{r['abstains']:>8}"
              f"{r['strict_precision_pct']:>13}%"
              f"{r['review_precision_pct']:>13}%")
    print(f"\nWritten to {OUT_CSV.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
