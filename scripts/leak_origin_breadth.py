"""Test the per-origin burst signature for route leaks.

A leak is a *burst* by a single network: one origin starts announcing
many of the victim's prefixes at once and then stops.  Route churn
involves many origins each touching a few prefixes, and an outage
involves the victim withdrawing its own.

The previous measurements looked at the leak detector's output, which
saturates, and at the raw announcement share, which is dominated by
unrelated transit.  This measurement uses the hijack detector's records
instead, because they are already computed per event and already carry
the prefix, the origin and the timestamp.  For every event it groups
the cross-origin announcements by origin and asks how many *distinct
victim prefixes* each origin announced, and how concentrated that
breadth is.

The signal is the maximum breadth reached by any single origin: a leak
should have one origin covering many of the victim's prefixes, while
churn should have many origins each covering a few.

Writes results/eval/leak_origin_breadth.json.
"""
from __future__ import annotations

import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.cache_resolution import resolve_cache  # noqa: E402

GT_CSV = PROJECT_ROOT / "data_check" / "ground_truth_collection" / "final_ground_truth.csv"
QUICK_DIR = PROJECT_ROOT / "results" / "quick"
OUT_PATH = PROJECT_ROOT / "results" / "eval" / "leak_origin_breadth.json"


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
                "gt_attacker_as": (r.get("attacker_as") or "").replace("AS", "").strip(),
            }
        )
    return out


def analyze(path: Path, ev: dict) -> dict:
    d = json.loads(path.read_text())
    routing = d.get("routing") or {}
    victim = ev["asn"]

    # prefix -> the set of origins that announced it
    prefixes_by_origin: dict[str, set] = defaultdict(set)
    origins_by_prefix: dict[str, set] = defaultdict(set)
    for rec in (routing.get("origin_hijacked") or []) + (routing.get("forge_hijacked") or []):
        if not isinstance(rec, dict):
            continue
        origin = str(rec.get("origin_as") or "").replace("AS", "").strip()
        if not origin or origin == victim:
            continue
        legit = {str(x).replace("AS", "").strip() for x in (rec.get("legitimate_origins") or [])}
        if victim not in legit and origin not in legit:
            continue
        pfx = str(rec.get("prefix") or "").strip()
        if not pfx:
            continue
        prefixes_by_origin[origin].add(pfx)
        origins_by_prefix[pfx].add(origin)

    breadth = {o: len(p) for o, p in prefixes_by_origin.items()}
    ordered = sorted(breadth.items(), key=lambda kv: -kv[1])
    actor = ev["gt_leak_as"] or ev["gt_attacker_as"]
    total_origins = len(breadth)
    top_count = ordered[0][1] if ordered else 0
    total_prefixes = len(origins_by_prefix)

    return {
        "event_id": ev["event_id"],
        "gt_cause": ev["gt_cause"],
        "victim": victim,
        "gt_actor": actor,
        "n_victim_prefixes": total_prefixes,
        "n_cross_origins": total_origins,
        "max_prefixes_per_origin": top_count,
        "top_origin": ordered[0][0] if ordered else "",
        "breadth_concentration": round(top_count / total_origins, 4) if total_origins else None,
        "breadth_share": round(top_count / total_prefixes, 4) if total_prefixes else None,
        "actor_prefix_count": breadth.get(actor, 0) if actor else 0,
        "actor_is_top": bool(actor and ordered and ordered[0][0] == actor),
        "top5": ordered[:5],
    }


def main() -> int:
    rows = []
    for ev in load_gt():
        match = resolve_cache(ev["asn"], ev["start"], ev["end"], QUICK_DIR)
        if not match or not match.path.exists():
            continue
        rows.append(analyze(match.path, ev))

    OUT_PATH.write_text(json.dumps(rows, indent=1, default=str))

    print(f"{'event_id':42s} {'gt':>8s} {'pfx':>6s} {'origins':>8s} "
          f"{'maxBreadth':>11s} {'conc':>7s} {'share':>7s} {'actor':>8s} {'aTop':>6s}")
    for cause in ("route_leak", "outage", "origin_hijack_victim"):
        grp = [r for r in rows if r["gt_cause"] == cause]
        if not grp:
            continue
        print(f"\n===== {cause} (n={len(grp)}) =====")
        for r in sorted(grp, key=lambda x: x["event_id"]):
            print(
                f"{r['event_id'][:42]:42s} {r['gt_cause'][:8]:>8s} "
                f"{r['n_victim_prefixes']:>6d} {r['n_cross_origins']:>8d} "
                f"{r['max_prefixes_per_origin']:>11d} "
                f"{str(r['breadth_concentration']):>7s} {str(r['breadth_share']):>7s} "
                f"{str(r['gt_actor'] or '-'):>8s} {str(r['actor_is_top'])[:5]:>6s}"
            )

    print()
    for cause in ("route_leak", "outage", "origin_hijack_victim"):
        grp = [r for r in rows if r["gt_cause"] == cause]
        if not grp:
            continue
        breadths = sorted(r["max_prefixes_per_origin"] for r in grp)
        concs = sorted(
            r["breadth_concentration"] for r in grp
            if isinstance(r["breadth_concentration"], (int, float))
        )
        conc_str = f"{concs[len(concs)//2]:.3f}" if concs else "n/a"
        print(f"{cause:22s} n={len(grp):2d} max_breadth median={breadths[len(breadths)//2]:>5d} "
              f"min={breadths[0]:>5d} max={breadths[-1]:>5d}   "
              f"concentration median={conc_str}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
