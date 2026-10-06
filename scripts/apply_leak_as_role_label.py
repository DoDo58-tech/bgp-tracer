#!/usr/bin/env python
"""Add the leak_as_role column to the canonical CSV.

The single row with a non-empty leak_as in a non-route_leak class
(hijack_cloudflare_1.1.1.1_2024, cause=origin_hijack_victim) carries
leak_as=AS262504 as a description of the secondary leak amplification,
not as a route_leak ground truth. Marking that explicitly prevents
readers from mis-scoring the row by reading the leak_as column
literally.

The new column is added next to leak_as; existing consumers ignore
unknown columns.
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CSV = ROOT / "data_check" / "ground_truth_collection" / "final_balanced_dataset_v16.csv"


def main():
    with CSV.open(newline="", encoding="utf-8-sig") as fh:
        rows = list(csv.DictReader(fh))
        fields = list(rows[0].keys()) if rows else []

    new_col = "leak_as_role"
    if new_col not in fields:
        if "leak_as" in fields:
            idx = fields.index("leak_as") + 1
        else:
            idx = len(fields)
        fields.insert(idx, new_col)

    counts: dict[str, int] = {}
    for r in rows:
        leak = (r.get("leak_as", "") or "").strip()
        cause = r.get("ground_truth_cause_label", "")
        if not leak:
            role = "n/a"
        elif cause == "route_leak":
            role = "primary_leaker"
        else:
            role = "auxiliary_amplifier"
        r[new_col] = role
        counts[role] = counts.get(role, 0) + 1

    with CSV.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

    print(f"leak_as_role column added to {CSV.relative_to(ROOT)}")
    print(f"counts: {counts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())