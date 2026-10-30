"""RFC 7908 path validation as a route-leak discriminator.

A route leak is a path that violates the AS adjacency relation: a
network announces another's prefix, and the announcement reaches the
victim's neighbours through an adjacency that the AS relationship
graph does not permit.  The AS relationship data (RFC 7908, one
snapshot per month) is already collected in ``data/asrel`` and is
already loaded by the routing pipeline, so this test asks the
question the corpus is actually asking: does the leaking event's
path violate the adjacency relation, and do the other classes' paths
not?

For each event the script

  * loads the AS relationship snapshot closest to the event date,
  * takes the paths the leak detector reported for the victim's
    prefixes,
  * validates each consecutive hop pair against the relationship
    graph (provider/customer, peer, or set in the same AS group),
  * reports the fraction of paths that violate the relation.

A high violation rate on the leak events and a low rate elsewhere is
the deployable version of the marker that ``leak_new_path_marker.py``
found using the ground truth's leaking ASN.

Writes results/eval/rfc7908_leak_validation.json.
"""

from __future__ import annotations

import csv
import json
import sys
from datetime import date
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.cache_resolution import resolve_cache  # noqa: E402

QUICK_DIR = PROJECT_ROOT / "results" / "quick"
ASREL_DIR = PROJECT_ROOT / "data" / "asrel"
GT_CSV = PROJECT_ROOT / "data_check" / "ground_truth_collection" / "final_ground_truth.csv"
OUT_PATH = PROJECT_ROOT / "results" / "eval" / "rfc7908_leak_validation.json"
CLASSES = ("outage", "route_leak", "origin_hijack_victim")


def load_events() -> list[dict]:
    sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
    from component_ablation_gt import load_gt

    return load_gt()


def snapshot_for(day: str) -> Path | None:
    """The relationship snapshot nearest to the event date."""
    try:
        target = date.fromisoformat(day[:10])
    except ValueError:
        return None
    best = None
    best_gap = None
    for path in ASREL_DIR.glob("*.parsed.json"):
        stamp = path.name.split(".")[0]
        try:
            snap = date.fromisoformat(
                f"{stamp[0:4]}-{stamp[4:6]}-{stamp[6:8]}"
            )
        except ValueError:
            continue
        gap = abs((snap - target).days)
        if best_gap is None or gap < best_gap:
            best_gap = gap
            best = path
    if best is None or (best_gap is not None and best_gap > 45):
        return None
    return best


def load_relations(path: Path) -> dict:
    """The set of adjacency pairs the relationship graph permits.

    The snapshot is a mapping of ``{"providers": {asn: [...]},
    "peers": {asn: [...]}}``: for each AS, the ASNs it announced to
    and the ASNs it shares a peering session with.  A path hop pair is
    permitted when the two are adjacent in either direction.
    """
    data = json.loads(path.read_text())
    allowed: set = set()
    for section in ("providers", "peers"):
        block = data.get(section) or {}
        if not isinstance(block, dict):
            continue
        for left, others in block.items():
            left_s = str(left).replace("AS", "").strip()
            if not left_s:
                continue
            for other in others or []:
                other_s = str(other).replace("AS", "").strip()
                if other_s:
                    allowed.add((left_s, other_s))
                    allowed.add((other_s, left_s))
    return allowed


def collect_paths(routing: dict) -> list[list]:
    paths = []
    for rec in routing.get("route_leaks") or []:
        if not isinstance(rec, dict):
            continue
        evidence = rec.get("evidence") or {}
        raw = str(evidence.get("as_path") or "")
        hops = [h.strip() for h in raw.split() if h.strip().isdigit()]
        if len(hops) >= 2:
            paths.append(hops)
    return paths


def main() -> int:
    import csv as _csv

    events = {e["event_id"]: e for e in load_events()}
    with open(GT_CSV, newline="") as fh:
        gt_rows = {r["event_id"]: r for r in _csv.DictReader(fh)}

    rel_cache: dict = {}
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

        snapshot = snapshot_for(ev["start"])
        if snapshot is None:
            rows.append({
                "event_id": eid, "gt_cause": ev["gt_cause"],
                "n_paths": 0, "violations": 0, "violation_rate": None,
                "no_snapshot": True, "leak_as": leak_as,
            })
            continue
        if snapshot not in rel_cache:
            rel_cache[snapshot] = load_relations(snapshot)
        allowed = rel_cache[snapshot]

        paths = collect_paths(routing)
        violations = 0
        checked = 0
        for hops in paths:
            for a, b in zip(hops, hops[1:]):
                checked += 1
                if (a, b) not in allowed:
                    violations += 1
                    break
        rows.append({
            "event_id": eid,
            "gt_cause": ev["gt_cause"],
            "n_paths": len(paths),
            "n_hops_checked": checked,
            "violations": violations,
            "violation_rate": round(violations / len(paths), 4) if paths else None,
            "no_snapshot": False,
            "leak_as": leak_as,
            "snapshot": snapshot.name,
        })

    print(f"{'event':42s} {'gt':22s} {'paths':>7s} {'viol':>6s} {'rate':>7s}")
    for r in sorted(rows, key=lambda x: (x["gt_cause"], x["event_id"])):
        rate = r["violation_rate"]
        rate_s = f"{rate:.3f}" if rate is not None else "-"
        print(f"{r['event_id']:42s} {r['gt_cause']:22s} {r['n_paths']:>7d} "
              f"{r['violations']:>6d} {rate_s:>7s}")

    print()
    for cls in CLASSES:
        sub = [r for r in rows if r["gt_cause"] == cls]
        rates = [r["violation_rate"] for r in sub if r["violation_rate"] is not None]
        print(f"{cls:24s} n={len(sub):2d} "
              f"median_rate={sorted(rates)[len(rates)//2] if rates else None} "
              f"n_any_violation={sum(1 for x in rates if x > 0)}")

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps({"rows": rows}, indent=1, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
