"""Measure the physical signature that separates leaks from hijacks.

A route leak and an origin hijack are both "the victim's prefixes are
being announced by someone else", but they differ in the AS path:

* in a **leak** the leaker re-exports the route it legitimately
  learned, so the legitimate origin AS is still present in the path;
* in a **hijack** the attacker originates the prefix itself, so the
  legitimate origin is *absent* from the path.

This script measures, per event, the share of cross-origin
announcements whose path still contains the victim, and checks whether
the ground-truth leaking/attacking ASN is among the cross-origin
origins.  It also records whether the victim's own announcement
survived in the window.
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


def load_gt() -> list[dict]:
    rows = list(csv.DictReader(GT_CSV.open()))
    out = []
    for r in rows:
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


def path_tokens(rec: dict) -> list[str]:
    raw = rec.get("as_path") or rec.get("as-path") or ""
    if isinstance(raw, list):
        return [str(x).replace("AS", "").strip() for x in raw if str(x).strip()]
    text = str(raw).replace("|", " ")
    return [t.replace("AS", "").strip() for t in text.split() if t.strip()]


def analyze(path: Path, ev: dict) -> dict:
    d = json.loads(path.read_text())
    routing = d.get("routing") or {}
    victim = ev["asn"]
    records = (routing.get("origin_hijacked") or []) + (routing.get("forge_hijacked") or [])
    traffic = d.get("traffic") or {}

    cross = 0
    cross_with_victim_in_path = 0
    cross_origin_as = Counter()
    cross_origin_victim_in_path = Counter()
    for rec in records:
        if not isinstance(rec, dict):
            continue
        origin = str(rec.get("origin_as") or "").replace("AS", "").strip()
        if not origin or origin == victim:
            continue
        legit = {str(x).replace("AS", "").strip() for x in (rec.get("legitimate_origins") or [])}
        if victim not in legit and origin not in legit:
            continue
        cross += 1
        cross_origin_as[origin] += 1
        tokens = path_tokens(rec)
        if victim in tokens:
            cross_with_victim_in_path += 1
            cross_origin_victim_in_path[origin] += 1

    gt_actor = ev["gt_leak_as"] or ev["gt_attacker_as"]
    return {
        "event_id": ev["event_id"],
        "gt_cause": ev["gt_cause"],
        "gt_actor": gt_actor,
        "victim": victim,
        "cross": cross,
        "cross_victim_in_path": cross_with_victim_in_path,
        "share_victim_in_path": (cross_with_victim_in_path / cross) if cross else None,
        "gt_actor_in_cross_origins": bool(gt_actor) and gt_actor in cross_origin_as,
        "gt_actor_cross_count": cross_origin_as.get(gt_actor, 0) if gt_actor else 0,
        "gt_actor_victim_in_path_count": cross_origin_victim_in_path.get(gt_actor, 0) if gt_actor else 0,
        "top_cross_origins": cross_origin_as.most_common(5),
        "traffic_available": bool(traffic.get("data_available", traffic.get("success"))),
    }


def main() -> None:
    rows = []
    for ev in load_gt():
        match = resolve_cache(ev["asn"], ev["start"], ev["end"], QUICK_DIR)
        if not match or not match.path.exists():
            rows.append({**ev, "cross": 0, "cross_victim_in_path": 0,
                         "share_victim_in_path": None,
                         "gt_actor_in_cross_origins": False,
                         "gt_actor_cross_count": 0,
                         "gt_actor_victim_in_path_count": 0,
                         "top_cross_origins": []})
            continue
        rows.append(analyze(match.path, ev))

    out = PROJECT_ROOT / "results" / "eval" / "leak_path_signature.json"
    out.write_text(json.dumps(rows, indent=1))

    print(f"{'event_id':44s} {'gt':>6s} {'actor':>7s} {'cross':>7s} {'vinpath':>7s} {'share':>6s} {'act?':>5s} {'actN':>6s} {'actVP':>6s}")
    for cause in ("route_leak", "outage", "origin_hijack_victim"):
        grp = [r for r in rows if r["gt_cause"] == cause]
        if not grp:
            continue
        print(f"\n===== {cause} (n={len(grp)}) =====")
        for r in sorted(grp, key=lambda x: x["event_id"]):
            share = r["share_victim_in_path"]
            share_s = f"{share:.3f}" if isinstance(share, (int, float)) else "-"
            print(
                f"{r['event_id'][:44]:44s} {r['gt_cause'][:6]:>6s} {str(r.get('gt_actor') or '-'):>7s} "
                f"{r['cross']:>7d} {r['cross_victim_in_path']:>7d} {share_s:>6s} "
                f"{str(r.get('gt_actor_in_cross_origins'))[:5]:>5s} "
                f"{r.get('gt_actor_cross_count', 0):>6d} {r.get('gt_actor_victim_in_path_count', 0):>6d}"
            )


if __name__ == "__main__":
    main()
