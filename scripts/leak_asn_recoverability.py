"""Can the leaking ASN be identified from the telemetry?

A route leak has a signature the other two classes do not: the
victim's prefix is announced with the *correct* origin but reached
through a *foreign* path.  The ground truth names the leaking ASN for
every leak event, which makes it possible to ask the decisive question
directly:

    does the routing block contain a record whose AS path contains the
    leaking ASN, for leak events, and not for the other classes?

If it does, the leak class is identifiable and the system's failure to
find it is a defect in the leak detector or in the cause rule.  If it
does not, the leak class is not recoverable from this telemetry and the
honest thing is to report that and to exclude the class from the
headline metric.

The script also reports the reverse direction: for the leaking ASN
known a priori, how many routing records name it.

Writes results/eval/leak_asn_recoverability.json.
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

QUICK_DIR = PROJECT_ROOT / "results" / "quick"
GT_CSV = PROJECT_ROOT / "data_check" / "ground_truth_collection" / "final_ground_truth.csv"
OUT_PATH = PROJECT_ROOT / "results" / "eval" / "leak_asn_recoverability.json"

CLASSES = ("outage", "route_leak", "origin_hijack_victim")


def load_gt_rows():
    with open(GT_CSV, newline="") as fh:
        return list(csv.DictReader(fh))


def collect_asns(blob):
    """Every AS number that appears anywhere in a record."""
    found = set()
    if isinstance(blob, str):
        tokens = blob.replace(",", " ").split()
        for tok in tokens:
            tok = tok.strip()
            if tok.isdigit() and 1 <= int(tok) <= 4294967294:
                found.add(tok)
    elif isinstance(blob, (list, tuple)):
        for item in blob:
            found |= collect_asns(item)
    elif isinstance(blob, dict):
        for value in blob.values():
            found |= collect_asns(value)
    return found


def main():
    gt_rows = {r["event_id"]: r for r in load_gt_rows()}
    events = {e["event_id"]: e for e in load_events()}

    rows = []
    for eid, ev in events.items():
        gt = gt_rows.get(eid) or {}
        leak_as = str(gt.get("leak_as") or "").replace("AS", "").strip()
        match = resolve_cache(
            ev["asn"], ev["start"], ev["end"], QUICK_DIR,
            event_id=eid, allow_same_date=False,
        )
        if match is None:
            continue
        quick = json.loads(match.path.read_text())
        routing = quick.get("routing") or {}

        # The set of AS numbers present in the routing block, split by
        # which sub-block they came from.
        leak_asns = collect_asns(routing.get("route_leaks") or [])
        hijack_asns = collect_asns(routing.get("origin_hijacked") or [])
        all_asns = leak_asns | hijack_asns

        rows.append({
            "event_id": eid,
            "gt_cause": ev["gt_cause"],
            "leak_as": leak_as,
            "leak_as_in_leak_records": bool(leak_as) and leak_as in leak_asns,
            "leak_as_in_hijack_records": bool(leak_as) and leak_as in hijack_asns,
            "leak_as_in_routing": bool(leak_as) and leak_as in all_asns,
            "n_leak_records": len(routing.get("route_leaks") or []),
            "n_hijack_records": len(routing.get("origin_hijacked") or []),
        })

    rates = {}
    for cls in CLASSES:
        sub = [r for r in rows if r["gt_cause"] == cls]
        rates[cls] = {
            "n": len(sub),
            "n_with_leak_as": sum(1 for r in sub if r["leak_as"]),
            "leak_as_in_leak_records": sum(
                1 for r in sub if r["leak_as_in_leak_records"]),
            "leak_as_in_hijack_records": sum(
                1 for r in sub if r["leak_as_in_hijack_records"]),
            "leak_as_in_routing": sum(1 for r in sub if r["leak_as_in_routing"]),
        }

    out = {
        "n": len(rows),
        "class_rates": rates,
        "rows": rows,
        "note": (
            "For a route leak the ground truth names the leaking ASN. The "
            "question is whether the routing block contains that ASN, which "
            "would make the class identifiable from telemetry."
        ),
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(out, indent=1, default=str))

    for cls, slot in rates.items():
        print(f"{cls:24s} n={slot['n']:2d} with_leak_as={slot['n_with_leak_as']:2d} "
              f"in_leak_records={slot['leak_as_in_leak_records']:2d} "
              f"in_hijack_records={slot['leak_as_in_hijack_records']:2d} "
              f"in_routing={slot['leak_as_in_routing']:2d}")
    print()
    print("leak events:")
    for r in rows:
        if r["gt_cause"] != "route_leak":
            continue
        print(f"  {r['event_id']:40s} leak_as={r['leak_as']:8s} "
              f"in_leak={r['leak_as_in_leak_records']} "
              f"in_hijack={r['leak_as_in_hijack_records']} "
              f"n_leak_recs={r['n_leak_records']:5d}")
    return 0


def load_events():
    sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
    from component_ablation_gt import load_gt

    return load_gt()


if __name__ == "__main__":
    raise SystemExit(main())
