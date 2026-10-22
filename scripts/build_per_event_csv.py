"""Convert hcaf_vs_baselines_30.jsonl into a per-event CSV table for paper §6.1.

Each row = one event. Columns capture ground-truth, each method's predicted
direction, and derived review/strict correctness flags.

This is the canonical script for the 30-event v17 ground-truth.

Reviewer-v2 §1.3.3 scoring:
  review_correct  = (pred == expected) OR (pred == "unknown")
  strict_correct  = (pred == expected)
  abstain         = (pred == "unknown")
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "results" / "eval" / "hcaf_vs_baselines_30.jsonl"
OUT_CSV = ROOT / "results" / "eval" / "per_event_30.csv"

METHODS = [
    ("hcaf", "hcaf_direction"),
    ("css", "css_direction"),
    ("pearson", "pearson_direction"),
    ("granger", "granger_direction"),
    ("ts_distance", "ts_distance_direction"),
    ("transfer_entropy", "transfer_entropy_direction"),
]


def is_review_correct(pred, expected):
    return pred == expected or pred == "unknown"


def is_strict_correct(pred, expected):
    return pred == expected


def is_abstain(pred):
    return pred == "unknown"


def main():
    EXCLUDE_CAUSES = {"origin_hijack_attacker"}

    rows = []
    with SRC.open() as f:
        for line in f:
            rec = json.loads(line)
            if rec.get("ground_truth_cause_label") in EXCLUDE_CAUSES:
                continue
            expected = rec.get("expected_direction")
            row = {
                "event_id": rec["event_id"],
                "tier": rec["tier"],
                "cause_label": rec["ground_truth_cause_label"],
                "expected_direction": expected,
                "cache_source": Path(rec["cache_source"]).name if rec.get("cache_source") else "synthetic",
                "hcaf_confidence": round(rec.get("hcaf_confidence", 0.0) or 0.0, 4),
                "css_is_causal": rec.get("css_is_causal", False),
                "css_p_value": rec.get("css_p_value", 1.0),
                "post_r2t": round((rec.get("posterior") or {}).get("routing_to_traffic", 0.0), 4),
                "post_t2r": round((rec.get("posterior") or {}).get("traffic_to_routing", 0.0), 4),
                "post_indep": round((rec.get("posterior") or {}).get("independent", 0.0), 4),
            }
            for short, key in METHODS:
                pred = rec.get(key, "unknown") or "unknown"
                row[f"{short}_pred"] = pred
                row[f"{short}_review"] = int(is_review_correct(pred, expected))
                row[f"{short}_strict"] = int(is_strict_correct(pred, expected))
                row[f"{short}_abstain"] = int(is_abstain(pred))
            rows.append(row)

    if not rows:
        raise SystemExit(f"No records found in {SRC}")

    fieldnames = list(rows[0].keys())
    with OUT_CSV.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

    print(f"Wrote {len(rows)} rows → {OUT_CSV.relative_to(ROOT)}")
    print()
    n = len(rows)
    real = [r for r in rows if 'synthetic' not in r['cache_source']]
    print(f"Real-cache events: {len(real)}/{n}")
    print()
    print(f"{'Method':<20} {'review%':>8} {'strict%':>8} {'abstain%':>9}  "
          f"{'real review%':>12} {'real strict%':>12} {'real abst%':>10}")
    print("-" * 96)
    for short, _ in METHODS:
        rev = sum(r[f"{short}_review"] for r in rows) / n * 100
        strict = sum(r[f"{short}_strict"] for r in rows) / n * 100
        abst = sum(r[f"{short}_abstain"] for r in rows) / n * 100
        n_real = len(real)
        rev_r = sum(r[f"{short}_review"] for r in real) / n_real * 100 if n_real else 0
        strict_r = sum(r[f"{short}_strict"] for r in real) / n_real * 100 if n_real else 0
        abst_r = sum(r[f"{short}_abstain"] for r in real) / n_real * 100 if n_real else 0
        print(f"{short:<20} {rev:>8.1f} {strict:>8.1f} {abst:>9.1f}  "
              f"{rev_r:>12.1f} {strict_r:>12.1f} {abst_r:>10.1f}")


if __name__ == "__main__":
    main()
