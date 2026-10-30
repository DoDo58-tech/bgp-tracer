"""Is a route leak identifiable from the victim's own telemetry?

Route leak is the class both arms do worst on: the deterministic rule
scores 0/10 and the agent pipeline 1/10.  Before concluding that the
class is unidentifiable, this script inspects every field the routing
block actually carries for the three classes and reports, for each
field, the rate at which it is populated per class.

A field that is populated for leaks and not for the other classes is a
candidate discriminator; a field populated for all three classes is a
detector artefact that carries no class information.

The candidate discriminators are then tested directly: for each leak
event, the script reports what the routing block says about the origin
of the victim's prefixes, because a leak announces the victim's prefix
with the *correct* origin and an anomalous path, while a hijack
announces it with a *wrong* origin.

Writes results/eval/leak_identifiability.json.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.cache_resolution import resolve_cache  # noqa: E402

QUICK_DIR = PROJECT_ROOT / "results" / "quick"
OUT_PATH = PROJECT_ROOT / "results" / "eval" / "leak_identifiability.json"

CLASSES = ("outage", "route_leak", "origin_hijack_victim")


def load_events() -> list[dict]:
    sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
    from component_ablation_gt import load_gt

    return load_gt()


def leak_record_shape(routing: dict) -> dict:
    """The shape of the leak detector's own output."""
    leaks = routing.get("route_leaks") or []
    shape = {
        "n_records": len(leaks),
        "truncated": bool(routing.get("leak_results_truncated")),
        "skipped": bool(routing.get("leak_analysis_skipped")),
        "leak_count": int(routing.get("leak_count") or 0),
        "leak_count_total": routing.get("leak_count_total"),
        "origin_announcements": routing.get("leak_origin_announcements"),
    }
    if leaks and isinstance(leaks[0], dict):
        shape["record_keys"] = sorted(leaks[0].keys())
        shape["sample"] = leaks[0]
    elif leaks:
        shape["sample_type"] = "string"
        shape["sample"] = str(leaks[0])[:400]
    return shape


def origin_profile(routing: dict, victim: str) -> dict:
    """How are the victim's prefixes announced?

    ``own``        the victim announces them (correct origin).
    ``cross``      a legitimate origin announces them for the victim
                   (a leak: right origin, wrong path).
    ``foreign``    a third AS announces them with a wrong origin
                   (a hijack).
    """
    profile = {"own": 0, "cross": 0, "foreign": 0, "records": 0}
    for rec in routing.get("origin_hijacked") or []:
        if not isinstance(rec, dict):
            continue
        profile["records"] += 1
        origin = str(rec.get("origin_as") or "")
        legit = {
            str(x).replace("AS", "")
            for x in (rec.get("legitimate_origins") or [])
        }
        victim_d = str(victim).replace("AS", "").strip()
        if origin and origin == victim_d:
            profile["own"] += 1
        elif origin and victim_d in legit:
            profile["cross"] += 1
        else:
            profile["foreign"] += 1
    return profile


def main() -> int:
    events = {e["event_id"]: e for e in load_events()}
    rows = []

    for eid, ev in events.items():
        match = resolve_cache(
            ev["asn"], ev["start"], ev["end"], QUICK_DIR,
            event_id=eid, allow_same_date=False,
        )
        if match is None:
            continue
        quick = json.loads(match.path.read_text())
        routing = quick.get("routing") or {}
        victim = str(
            routing.get("target_asn") or routing.get("asn") or ev["asn"]
        ).replace("AS", "").strip()
        rows.append({
            "event_id": eid,
            "gt_cause": ev["gt_cause"],
            "asn": ev["asn"],
            "leak": leak_record_shape(routing),
            "origin_profile": origin_profile(routing, victim),
        })

    # Field population rate per class.
    rates: dict = {}
    for cls in CLASSES:
        sub = [r for r in rows if r["gt_cause"] == cls]
        rates[cls] = {
            "n": len(sub),
            "leak_truncated": sum(1 for r in sub if r["leak"]["truncated"]),
            "leak_skipped": sum(1 for r in sub if r["leak"]["skipped"]),
            "leak_saturated": sum(
                1 for r in sub
                if r["leak"]["truncated"] or r["leak"]["n_records"] >= 5000
            ),
            "origin_own": sum(1 for r in sub if r["origin_profile"]["own"] > 0),
            "origin_cross": sum(1 for r in sub if r["origin_profile"]["cross"] > 0),
            "origin_foreign": sum(
                1 for r in sub if r["origin_profile"]["foreign"] > 0),
        }

    out = {"n": len(rows), "class_rates": rates, "rows": rows}
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(out, indent=1, default=str))

    print("field population per class:")
    keys = ("leak_truncated", "leak_skipped", "leak_saturated",
            "origin_own", "origin_cross", "origin_foreign")
    print(f"{'field':18s} " + " ".join(f"{c:>22s}" for c in CLASSES))
    for k in keys:
        cells = []
        for c in CLASSES:
            slot = rates[c]
            cells.append(f"{slot[k]:3d}/{slot['n']:<3d}")
        print(f"{k:18s} " + " ".join(f"{x:>22s}" for x in cells))
    print()
    print("leak-class events, origin profile and leak detector shape:")
    for r in rows:
        if r["gt_cause"] != "route_leak":
            continue
        p = r["origin_profile"]
        lk = r["leak"]
        print(
            f"  {r['event_id']:40s} own={p['own']:4d} cross={p['cross']:4d} "
            f"foreign={p['foreign']:5d} recs={lk['n_records']:5d} "
            f"trunc={lk['truncated']} count={lk['leak_count']:5d}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
