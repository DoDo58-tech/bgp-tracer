"""The confusion matrix and the hard-case subsets, on the canonical corpus.

Writes results/eval/robustness_subsets.json, which backs the appendix
tables.
"""

from __future__ import annotations

import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EVAL = PROJECT_ROOT / "results" / "eval"
OUT_PATH = EVAL / "robustness_subsets.json"

CLASSES = ("outage", "route_leak", "origin_hijack_victim")


def main():
    records = json.loads((EVAL / "gt_agent_full.json").read_text())["records"]
    feat = {
        r["event_id"]: r
        for r in json.loads((EVAL / "cause_feature_table.json").read_text())["rows"]
    }

    confusion = {gt: {p: 0 for p in CLASSES} for gt in CLASSES}
    subsets = {
        "all": [],
        "with_traffic": [],
        "withdrawal_storm": [],
        "hijack_dominant": [],
    }

    for r in records:
        gt = r.get("gt_cause")
        pred = r.get("cause")
        if gt in confusion and pred in CLASSES:
            confusion[gt][pred] += 1

        f = feat.get(r["event_id"], {})
        ok = pred == gt
        subsets["all"].append(ok)
        if f.get("traffic_available"):
            subsets["with_traffic"].append(ok)
        if int(f.get("withdrawal_count") or 0) >= 100:
            subsets["withdrawal_storm"].append(ok)
        if f.get("has_origin_hijack"):
            subsets["hijack_dominant"].append(ok)

    out = {
        "n": len(records),
        "confusion": confusion,
        "subsets": {
            name: {
                "n": len(vals),
                "correct": sum(1 for v in vals if v),
                "accuracy": round(sum(1 for v in vals if v) / len(vals), 4)
                if vals else None,
            }
            for name, vals in subsets.items()
        },
    }
    OUT_PATH.write_text(json.dumps(out, indent=1, default=str))

    print("confusion (rows = truth, cols = predicted):")
    for gt in CLASSES:
        row = confusion[gt]
        n = sum(row.values())
        print(f"  {gt:24s} " + "  ".join(
            f"{p}={row[p]}({row[p]/n:.0%})" for p in CLASSES))
    print()
    for name, slot in out["subsets"].items():
        print(f"{name:22s} {slot['correct']}/{slot['n']} = {slot['accuracy']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
