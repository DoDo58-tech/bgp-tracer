"""Origin change versus path change: the leak/hijack discriminator.

The outage analyser already computes two change features over the event
window, against the same features measured over the baseline window:

  ori_change_rate    how often the origin ASN of the victim's prefixes
                     changed.  An origin hijack changes the origin.
  path_change_rate   how often the AS path to the victim's prefixes
                     changed.  A route leak keeps the correct origin
                     and changes the path.

This script measures both features per class, and tests the rule they
suggest: a leak is an event where the path changed and the origin did
not.

Writes results/eval/origin_path_change.json.
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
OUT_PATH = PROJECT_ROOT / "results" / "eval" / "origin_path_change.json"
CLASSES = ("outage", "route_leak", "origin_hijack_victim")


def load_events() -> list[dict]:
    sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
    from component_ablation_gt import load_gt

    return load_gt()


def changes(outage: dict) -> dict:
    features = outage.get("event_features") or {}
    baseline = outage.get("baseline_features") or {}

    def base(name):
        slot = baseline.get(name)
        if isinstance(slot, dict):
            return float(slot.get("mean") or 0.0)
        return float(slot or 0.0)

    def feature(name):
        return float(features.get(name) or 0.0)

    ori_event = feature("num_ori_change")
    path_event = feature("origin_change_count")
    ori_rate = feature("ori_change_rate")
    path_rate = feature("path_change_rate")
    ori_base = base("num_ori_change")
    path_base = base("path_change_count")

    return {
        "ori_change_rate": ori_rate,
        "path_change_rate": path_rate,
        "num_ori_change": ori_event,
        "origin_change_count": path_event,
        "ori_change_excess": round(ori_event - ori_base, 4),
        "path_change_excess": round(path_event - path_base, 4),
    }


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
        outage = routing.get("outage_analysis") or {}
        rows.append({
            "event_id": eid,
            "gt_cause": ev["gt_cause"],
            **changes(outage),
        })

    print(f"{'event':42s} {'gt':22s} {'ori_rate':>10s} {'path_rate':>10s} "
          f"{'ori_exc':>9s} {'path_exc':>9s}")
    for r in sorted(rows, key=lambda x: (x["gt_cause"], x["event_id"])):
        print(
            f"{r['event_id']:42s} {r['gt_cause']:22s} "
            f"{r['ori_change_rate']:>10.5f} {r['path_change_rate']:>10.5f} "
            f"{r['ori_change_excess']:>9} {r['path_change_excess']:>9}"
        )

    print()
    for cls in CLASSES:
        sub = [r for r in rows if r["gt_cause"] == cls]
        ori = sorted(r["ori_change_excess"] for r in sub)
        path = sorted(r["path_change_excess"] for r in sub)
        print(f"{cls:22s} n={len(sub):2d} "
              f"ori_excess median={ori[len(ori)//2]:>10} min={ori[0]:>10} max={ori[-1]:>10}")
        print(f"{'':22s}   path_excess median={path[len(path)//2]:>10} "
              f"min={path[0]:>10} max={path[-1]:>10}")

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps({"rows": rows}, indent=1, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
