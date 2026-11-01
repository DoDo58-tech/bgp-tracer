"""Test whether the leak records concentrate on one ASN.

The PathProb leak detector reports a *set* of flagged paths.  For a
real leak the flagged paths should come from a single leaking network,
because one network is the one leaking.  For an outage or a hijack the
flagged paths are churn -- the target's own routes re-routed by many
unrelated networks -- so they should be spread across many origins.

If that holds, the concentration of the leak records is a class signal
that the current rule does not read: the rule uses the leak *count*,
which saturates at the truncation limit for every event in the corpus
and therefore carries no class information.

This script measures the concentration on the cached routing blocks.
"""
from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.cache_resolution import resolve_cache  # noqa: E402

GT_CSV = PROJECT_ROOT / "data_check" / "ground_truth_collection" / "final_ground_truth.csv"
QUICK_DIR = PROJECT_ROOT / "results" / "quick"
OUT_PATH = PROJECT_ROOT / "results" / "eval" / "leak_concentration.json"


def load_gt():
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


def record_origin(event: dict):
    """The origin AS of a leak record's flagged path."""
    evidence = event.get("evidence") or {}
    path = evidence.get("as_path") or event.get("as-path") or ""
    tokens = [t for t in str(path).replace("|", " ").split() if t]
    return tokens[-1] if tokens else ""


def record_victim_in_path(event: dict, victim: str):
    evidence = event.get("evidence") or {}
    path = evidence.get("as_path") or event.get("as-path") or ""
    tokens = [t for t in str(path).replace("|", " ").split() if t]
    return victim in tokens


def analyze(path: Path, ev: dict):
    d = json.loads(path.read_text())
    routing = d.get("routing") or {}
    victim = ev["asn"]
    leaks = routing.get("route_leaks") or []

    origins = Counter()
    victim_in_path = 0
    for rec in leaks:
        if not isinstance(rec, dict):
            continue
        origin = record_origin(rec)
        if not origin:
            continue
        origins[origin] += 1
        if record_victim_in_path(rec, victim):
            victim_in_path += 1

    total = sum(origins.values())
    top_share = (origins.most_common(1)[0][1] / total) if origins else 0.0
    actor = ev["gt_leak_as"] or ev["gt_attacker_as"]
    return {
        "event_id": ev["event_id"],
        "gt_cause": ev["gt_cause"],
        "victim": victim,
        "gt_actor": actor,
        "n_leak_records": len(leaks),
        "n_with_origin": total,
        "n_distinct_origins": len(origins),
        "top_origin": origins.most_common(1)[0][0] if origins else "",
        "top_origin_count": origins.most_common(1)[0][1] if origins else 0,
        "top_origin_share": round(top_share, 4),
        "victim_in_path_count": victim_in_path,
        "victim_in_path_share": round(victim_in_path / total, 4) if total else None,
        "actor_is_top_origin": bool(actor and origins and origins.most_common(1)[0][0] == actor),
        "actor_origin_count": origins.get(actor, 0) if actor else 0,
        "actor_share": round(origins.get(actor, 0) / total, 4) if actor and total else None,
    }


def main():
    rows = []
    for ev in load_gt():
        match = resolve_cache(ev["asn"], ev["start"], ev["end"], QUICK_DIR)
        if not match or not match.path.exists():
            continue
        rows.append(analyze(match.path, ev))

    OUT_PATH.write_text(json.dumps(rows, indent=1, default=str))

    print(f"{'event_id':42s} {'gt':>8s} {'recs':>6s} {'distinct':>8s} "
          f"{'topShare':>9s} {'actor':>8s} {'aShare':>7s} {'aIsTop':>7s}")
    for cause in ("route_leak", "outage", "origin_hijack_victim"):
        grp = [r for r in rows if r["gt_cause"] == cause]
        if not grp:
            continue
        print(f"\n===== {cause} (n={len(grp)}) =====")
        for r in sorted(grp, key=lambda x: x["event_id"]):
            print(
                f"{r['event_id'][:42]:42s} {r['gt_cause'][:8]:>8s} "
                f"{r['n_with_origin']:>6d} {r['n_distinct_origins']:>8d} "
                f"{r['top_origin_share']:>9} {str(r['gt_actor'] or '-'):>8s} "
                f"{str(r['actor_share']):>7s} {str(r['actor_is_top_origin'])[:6]:>7s}"
            )

    print()
    for cause in ("route_leak", "outage", "origin_hijack_victim"):
        grp = [r for r in rows if r["gt_cause"] == cause]
        if not grp:
            continue
        shares = sorted(r["top_origin_share"] for r in grp)
        print(f"{cause:22s} n={len(grp):2d} top_origin_share median={shares[len(shares)//2]:.4f} "
              f"min={shares[0]:.4f} max={shares[-1]:.4f}")

    # Does the ground-truth actor show up as a leak-record origin?
    leaks = [r for r in rows if r["gt_cause"] == "route_leak"]
    others = [r for r in rows if r["gt_cause"] != "route_leak"]
    actor_hit = sum(1 for r in leaks if r["actor_origin_count"] > 0)
    actor_top = sum(1 for r in leaks if r["actor_is_top_origin"])
    false_hit = sum(1 for r in others if r["actor_origin_count"] > 0)
    print()
    print(f"leak events whose GT actor appears among leak-record origins: "
          f"{actor_hit}/{len(leaks)} (is the top origin in {actor_top})")
    print(f"non-leak events whose GT actor appears among leak-record origins: "
          f"{false_hit}/{len(others)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
