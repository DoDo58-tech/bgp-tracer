"""Convert hcaf_vs_baselines_v36.jsonl into a per-event CSV table for paper §6.1.

Each row = one event. Columns capture ground-truth, each method's predicted
direction, and derived review/strict correctness flags.

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
SRC = ROOT / "results" / "eval" / "hcaf_vs_baselines_v36.jsonl"
OUT_CSV = ROOT / "results" / "eval" / "per_event_v36.csv"

METHODS = [
    ("hcaf", "hcaf_direction"),
    ("css", "css_direction"),
    ("pearson", "pearson_direction"),
    ("granger", "granger_direction"),
    ("ts_distance", "ts_distance_direction"),
    ("transfer_entropy", "transfer_entropy_direction"),
]


def is_review_correct(pred: str, expected: str) -> bool:
    return pred == expected or pred == "unknown"


def is_strict_correct(pred: str, expected: str) -> bool:
    return pred == expected


def is_abstain(pred: str) -> bool:
    return pred == "unknown"


def main() -> None:
    # Derived attacker-view rows are excluded from §6.2 aggregates to avoid
    # double-counting the same physical incidents from the attacker's side.
    # (Scripts/eval_hcaf_vs_baselines.py uses the same exclusion.)
    EXCLUDE_CAUSES = {"origin_hijack_attacker"}

    rows = []
    with SRC.open() as f:
        for line in f:
            rec = json.loads(line)
            if rec.get("ground_truth_cause_label") in EXCLUDE_CAUSES:
                continue
            expected = rec["expected_direction"]
            row = {
                "event_id": rec["event_id"],
                "tier": rec["tier"],
                "cause_label": rec["ground_truth_cause_label"],
                "expected_direction": expected,
                "cache_source": Path(rec["cache_source"]).name,
                "hcaf_confidence": round(rec.get("hcaf_confidence", 0.0), 4),
                "css_is_causal": rec.get("css_is_causal", False),
                "css_p_value": rec.get("css_p_value", 1.0),
                "post_r2t": round(rec.get("posterior", {}).get("routing_to_traffic", 0.0), 4),
                "post_t2r": round(rec.get("posterior", {}).get("traffic_to_routing", 0.0), 4),
                "post_indep": round(rec.get("posterior", {}).get("independent", 0.0), 4),
            }
            for short, key in METHODS:
                pred = rec.get(key, "unknown")
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
    print("Columns:", fieldnames)
    print()
    # Per-method summary
    print(f"{'Method':<20} {'review%':>8} {'strict%':>8} {'abstain%':>9}")
    print("-" * 48)
    for short, _ in METHODS:
        n = len(rows)
        rev = sum(r[f"{short}_review"] for r in rows) / n * 100
        strict = sum(r[f"{short}_strict"] for r in rows) / n * 100
        abst = sum(r[f"{short}_abstain"] for r in rows) / n * 100
        print(f"{short:<20} {rev:>8.1f} {strict:>8.1f} {abst:>9.1f}")


if __name__ == "__main__":
    main()
