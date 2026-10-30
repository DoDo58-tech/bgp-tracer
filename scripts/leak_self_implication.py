"""Does the leak detector report leaks *about the monitored AS*?

The previous discriminator failed because foreign AS numbers appear on
every event's paths.  The sharper question is whether the leak
detector's own records are *about the AS being analysed*: a leak
record whose ``claimed_as`` is the monitored AS, or whose affected
prefixes are served by the monitored AS, is evidence that this AS was
leaked.  A leak record about some other AS is not evidence about this
event.

This script measures that directly: for each event it counts the leak
records that implicate the monitored AS, and reports the rate per class.

Writes results/eval/leak_self_implication.json.
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
OUT_PATH = PROJECT_ROOT / "results" / "eval" / "leak_self_implication.json"

CLASSES = ("outage", "route_leak", "origin_hijack_victim")


def load_events() -> list[dict]:
    sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
    from component_ablation_gt import load_gt

    return load_gt()


def self_implicating_leaks(routing: dict, victim: str) -> dict:
    victim_d = str(victim).replace("AS", "").strip()
    leaks = routing.get("route_leaks") or []
    out = {
        "n_records": len(leaks),
        "claimed_as_self": 0,
        "victim_as_self": 0,
        "path_ends_at_self": 0,
        "prefix_nonempty": 0,
        "any_self": 0,
    }
    for rec in leaks:
        if not isinstance(rec, dict):
            continue
        claimed = str(rec.get("claimed_as") or "").replace("AS", "").strip()
        rec_victim = str(rec.get("victim_as") or "").replace("AS", "").strip()
        evidence = rec.get("evidence") or {}
        path = str(evidence.get("as_path") or "")
        path_hops = path.split()
        prefix = rec.get("affected_prefixes") or []

        hit = False
        if claimed and claimed == victim_d:
            out["claimed_as_self"] += 1
            hit = True
        if rec_victim and rec_victim == victim_d:
            out["victim_as_self"] += 1
            hit = True
        if path_hops and path_hops[-1] == victim_d:
            out["path_ends_at_self"] += 1
            hit = True
        if prefix:
            out["prefix_nonempty"] += 1
        if hit:
            out["any_self"] += 1
    return out


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
            "self": self_implicating_leaks(routing, victim),
        })

    rates = {}
    for cls in CLASSES:
        sub = [r for r in rows if r["gt_cause"] == cls]
        rates[cls] = {
            "n": len(sub),
            "n_with_any_self": sum(1 for r in sub if r["self"]["any_self"] > 0),
            "n_claimed_as_self": sum(
                1 for r in sub if r["self"]["claimed_as_self"] > 0),
            "n_path_ends_at_self": sum(
                1 for r in sub if r["self"]["path_ends_at_self"] > 0),
            "median_self_records": sorted(
                r["self"]["any_self"] for r in sub)[len(sub) // 2] if sub else None,
            "self_record_counts": sorted(r["self"]["any_self"] for r in sub),
        }

    # The rule: an event is a leak when the leak detector reported
    # records that implicate the monitored AS itself.
    def rule(r):
        return r["self"]["any_self"] > 0

    hits = 0
    for r in rows:
        pred = "route_leak" if rule(r) else "not_leak"
        actual = "route_leak" if r["gt_cause"] == "route_leak" else "not_leak"
        if pred == actual:
            hits += 1

    out = {
        "n": len(rows),
        "class_rates": rates,
        "rule_accuracy": round(hits / len(rows), 4),
        "rows": rows,
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(out, indent=1, default=str))

    for cls, slot in rates.items():
        print(f"{cls:24s} n={slot['n']:2d} any_self={slot['n_with_any_self']:2d} "
              f"claimed_self={slot['n_claimed_as_self']:2d} "
              f"path_ends_self={slot['n_path_ends_at_self']:2d}")
        print(f"    self record counts: {slot['self_record_counts']}")
    print(f"\nrule 'leak records implicate the monitored AS': {hits}/{len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
