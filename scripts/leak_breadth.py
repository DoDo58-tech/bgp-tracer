"""Test the breadth signature for route leaks.

A route leak is usually a *breadth* event.  A network that
misconfigures a session export exports its whole table, or a large
fraction of it: the leak's announcement covers thousands of prefixes
at once.  Route churn, by contrast, affects a handful of prefixes at a
time, and so does an outage.

The PathProb leak detector reports a path-level score, so it fires
equally on breadth and on churn, and it saturates at its truncation
limit on most events of every class.  What it does report, though, is
*which prefixes* were flagged, and the number of distinct prefixes is
a property the current cause rule never reads: the rule uses the leak
*count*, which the truncation limit makes uninformative.

This script measures the breadth of the flagged prefix set per event
and reports whether it separates the classes.
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.cache_resolution import resolve_cache  # noqa: E402

GT_CSV = PROJECT_ROOT / "data_check" / "ground_truth_collection" / "final_ground_truth.csv"
QUICK_DIR = PROJECT_ROOT / "results" / "quick"
OUT_PATH = PROJECT_ROOT / "results" / "eval" / "leak_breadth.json"


def load_gt() -> list[dict]:
    out = []
    for r in csv.DictReader(GT_CSV.open()):
        out.append(
            {
                "event_id": r["event_id"],
                "asn": str(r.get("victim_as") or "").replace("AS", "").strip(),
                "start": (r.get("start_utc") or "").strip(),
                "end": (r.get("end_utc") or "").strip(),
                "gt_cause": (r.get("cause") or "").strip(),
                "gt_leak_as": (r.get("leak_as") or "").replace("AS", "").strip(),
            }
        )
    return out


def analyze(path: Path, ev: dict) -> dict:
    d = json.loads(path.read_text())
    routing = d.get("routing") or {}
    leaks = routing.get("route_leaks") or []

    prefixes = set()
    probabilities = []
    paths = set()
    for rec in leaks:
        if not isinstance(rec, dict):
            continue
        for pfx in (rec.get("affected_prefixes") or []):
            if pfx:
                prefixes.add(str(pfx))
        evidence = rec.get("evidence") or {}
        prob = evidence.get("leak_probability")
        if isinstance(prob, (int, float)):
            probabilities.append(float(prob))
        as_path = evidence.get("as_path")
        if as_path:
            paths.add(str(as_path))

    victim = ev["asn"]
    victim_originated = 0
    for rec in leaks:
        if not isinstance(rec, dict):
            continue
        evidence = rec.get("evidence") or {}
        tokens = str(evidence.get("as_path") or "").replace("|", " ").split()
        if tokens and tokens[-1] == victim:
            victim_originated += 1

    return {
        "event_id": ev["event_id"],
        "gt_cause": ev["gt_cause"],
        "victim": victim,
        "n_leak_records": len(leaks),
        "n_distinct_prefixes": len(prefixes),
        "n_distinct_paths": len(paths),
        "n_victim_originated": victim_originated,
        "min_probability": round(min(probabilities), 4) if probabilities else None,
        "max_probability": round(max(probabilities), 4) if probabilities else None,
        "truncated": bool(routing.get("leak_results_truncated")),
    }


def main() -> int:
    rows = []
    for ev in load_gt():
        match = resolve_cache(ev["asn"], ev["start"], ev["end"], QUICK_DIR)
        if not match or not match.path.exists():
            continue
        rows.append(analyze(match.path, ev))

    OUT_PATH.write_text(json.dumps(rows, indent=1, default=str))

    print(f"{'event_id':42s} {'gt':>8s} {'records':>8s} {'prefixes':>9s} "
          f"{'paths':>6s} {'minProb':>8s} {'trunc':>6s}")
    for cause in ("route_leak", "outage", "origin_hijack_victim"):
        grp = [r for r in rows if r["gt_cause"] == cause]
        if not grp:
            continue
        print(f"\n===== {cause} (n={len(grp)}) =====")
        for r in sorted(grp, key=lambda x: x["event_id"]):
            print(
                f"{r['event_id'][:42]:42s} {r['gt_cause'][:8]:>8s} "
                f"{r['n_leak_records']:>8d} {r['n_distinct_prefixes']:>9d} "
                f"{r['n_distinct_paths']:>6d} {str(r['min_probability']):>8s} "
                f"{str(r['truncated'])[:5]:>6s}"
            )

    print()
    for cause in ("route_leak", "outage", "origin_hijack_victim"):
        grp = [r for r in rows if r["gt_cause"] == cause]
        if not grp:
            continue
        breadths = sorted(r["n_distinct_prefixes"] for r in grp)
        print(f"{cause:22s} n={len(grp):2d} distinct_prefixes "
              f"min={breadths[0]:>6d} median={breadths[len(breadths)//2]:>6d} "
              f"max={breadths[-1]:>6d}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
