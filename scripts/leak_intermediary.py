"""Test the leaky-intermediary signature for route leaks.

A leak detector that watches the victim sees the victim's *own*
announcement re-appearing with an extra hop in the path: the leaker
exports the victim's prefix to a provider, and the victim's route comes
back with the leaker in the middle of the path.  The origin is still
the victim, so the announcement is still the victim's own -- but the
path now contains a network that is not one of the victim's ordinary
providers.

That gives a discriminator the current rule does not use: the leaking
ASN is an *intermediary* on the victim's own flagged paths.  The
ground truth names the leaking ASN for every leak event, so the
measurement below checks whether that ASN is an intermediary on the
victim's flagged paths, and whether it also shows up for the other two
classes (where the ground truth names no leaker at all).

The comparison is made against the victim's *unflagged* paths in the
same window, so an intermediary that is simply one of the victim's
ordinary providers does not count.
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
OUT_PATH = PROJECT_ROOT / "results" / "eval" / "leak_intermediary.json"


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


def path_tokens(record: dict) -> list[str]:
    evidence = record.get("evidence") or {}
    raw = evidence.get("as_path") or record.get("as-path") or record.get("as_path") or ""
    return [t for t in str(raw).replace("|", " ").split() if t]


def intermediaries(record: dict, victim: str) -> set[str]:
    """Hops between the origin and the victim, excluding both ends."""
    tokens = path_tokens(record)
    if len(tokens) < 2:
        return set()
    origin = tokens[-1]
    hops = set(tokens[:-1])
    hops.discard(origin)
    hops.discard(victim)
    return hops


def analyze(path: Path, ev: dict) -> dict:
    d = json.loads(path.read_text())
    routing = d.get("routing") or {}
    victim = ev["asn"]
    leaks = routing.get("route_leaks") or []

    flagged_intermediaries: Counter = Counter()
    n_flagged = 0
    for rec in leaks:
        if not isinstance(rec, dict):
            continue
        tokens = path_tokens(rec)
        if not tokens or tokens[-1] != victim:
            continue
        n_flagged += 1
        flagged_intermediaries.update(intermediaries(rec, victim))

    # The victim's ordinary providers: the intermediaries seen on the
    # hijack-detector records that are *not* leak-flagged.
    ordinary: Counter = Counter()
    for rec in (routing.get("origin_hijacked") or [])[:2000]:
        if not isinstance(rec, dict):
            continue
        tokens = path_tokens(rec)
        if not tokens or tokens[-1] != victim:
            continue
        ordinary.update(intermediaries(rec, victim))

    actor = ev["gt_leak_as"] or ev["gt_attacker_as"]
    novel = {a for a in flagged_intermediaries if a not in ordinary}
    return {
        "event_id": ev["event_id"],
        "gt_cause": ev["gt_cause"],
        "victim": victim,
        "gt_actor": actor,
        "n_flagged_paths": n_flagged,
        "n_distinct_intermediaries": len(flagged_intermediaries),
        "n_novel_intermediaries": len(novel),
        "actor_is_intermediary": bool(actor and actor in flagged_intermediaries),
        "actor_is_novel_intermediary": bool(actor and actor in novel),
        "actor_intermediary_count": flagged_intermediaries.get(actor, 0) if actor else 0,
        "top_novel_intermediaries": sorted(novel)[:10],
    }


def main() -> int:
    rows = []
    for ev in load_gt():
        match = resolve_cache(ev["asn"], ev["start"], ev["end"], QUICK_DIR)
        if not match or not match.path.exists():
            continue
        rows.append(analyze(match.path, ev))

    OUT_PATH.write_text(json.dumps(rows, indent=1, default=str))

    print(f"{'event_id':42s} {'gt':>8s} {'flagged':>8s} {'distinct':>9s} "
          f"{'novel':>6s} {'actor':>8s} {'aIsInter':>10s} {'aNovel':>7s}")
    for cause in ("route_leak", "outage", "origin_hijack_victim"):
        grp = [r for r in rows if r["gt_cause"] == cause]
        if not grp:
            continue
        print(f"\n===== {cause} (n={len(grp)}) =====")
        for r in sorted(grp, key=lambda x: x["event_id"]):
            print(
                f"{r['event_id'][:42]:42s} {r['gt_cause'][:8]:>8s} "
                f"{r['n_flagged_paths']:>8d} {r['n_distinct_intermediaries']:>9d} "
                f"{r['n_novel_intermediaries']:>6d} {str(r['gt_actor'] or '-'):>8s} "
                f"{str(r['actor_is_intermediary'])[:9]:>10s} "
                f"{str(r['actor_is_novel_intermediary'])[:6]:>7s}"
            )

    leaks = [r for r in rows if r["gt_cause"] == "route_leak"]
    others = [r for r in rows if r["gt_cause"] != "route_leak"]
    print()
    print(f"leak events where GT leaker is an intermediary on the victim's "
          f"flagged paths: {sum(1 for r in leaks if r['actor_is_intermediary'])}/{len(leaks)}")
    print(f"leak events where GT leaker is a *novel* intermediary: "
          f"{sum(1 for r in leaks if r['actor_is_novel_intermediary'])}/{len(leaks)}")
    print(f"non-leak events where GT leaker appears as an intermediary: "
          f"{sum(1 for r in others if r['actor_is_intermediary'])}/{len(others)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
