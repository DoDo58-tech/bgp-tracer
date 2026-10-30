"""Audit the collection mode of every cached event.

Several caches carry ``hijack_analysis_skipped: true`` with the reason
``light_mode``.  In light mode the detector does not build the
expected-origin baseline, so it cannot tell the victim's own
announcement from a hijacked one, and it flags the victim against
itself.  If a substantial share of the corpus was collected in light
mode, then the classes the corpus labels are not separable by the
telemetry that was actually kept, and the resulting accuracy bounds
measure the collection pipeline rather than the method.

This script reports, per event and per class:

  * the collection mode (light or full),
  * whether the expected-origin baseline was available,
  * whether the hijack detector ran to completion,
  * the withdrawal baseline's presence,

and the class distribution of light-mode events.

Writes results/eval/collection_mode_audit.json.
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
OUT_PATH = PROJECT_ROOT / "results" / "eval" / "collection_mode_audit.json"

CLASSES = ("outage", "route_leak", "origin_hijack_victim")


def load_events() -> list[dict]:
    sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
    from component_ablation_gt import load_gt

    return load_gt()


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
        traffic = quick.get("traffic") or {}
        warnings = quick.get("warnings") or []

        origin_hijacked = routing.get("origin_hijacked") or []
        expected_origin_null = 0
        for rec in origin_hijacked:
            if isinstance(rec, dict) and rec.get("expected_origin") in (None, ""):
                expected_origin_null += 1

        rows.append({
            "event_id": eid,
            "gt_cause": ev["gt_cause"],
            "asn": ev["asn"],
            "hijack_skipped": bool(routing.get("hijack_analysis_skipped")),
            "hijack_records": len(origin_hijacked),
            "expected_origin_null": expected_origin_null,
            "all_expected_origin_null": bool(origin_hijacked) and (
                expected_origin_null == len(origin_hijacked)
            ),
            "light_mode": bool(routing.get("hijack_analysis_skipped")),
            "leak_skipped": bool(routing.get("leak_analysis_skipped")),
            "outage_skipped": bool(routing.get("outage_analysis_skipped")),
            "outage_has_event_features": bool(
                (routing.get("outage_analysis") or {}).get("event_features")
            ),
            "traffic_baseline_weeks": traffic.get("baseline_weeks_available"),
            "warnings": warnings if isinstance(warnings, list) else [],
        })

    light = [r for r in rows if r["light_mode"]]
    full = [r for r in rows if not r["light_mode"]]

    class_dist = {}
    for cls in CLASSES:
        class_dist[cls] = {
            "n": len([r for r in rows if r["gt_cause"] == cls]),
            "light": len([r for r in light if r["gt_cause"] == cls]),
            "full": len([r for r in full if r["gt_cause"] == cls]),
        }

    out = {
        "n": len(rows),
        "n_light_mode": len(light),
        "n_full_mode": len(full),
        "light_mode_events": [r["event_id"] for r in light],
        "class_distribution": class_dist,
        "n_expected_origin_null_all": sum(
            1 for r in rows if r["all_expected_origin_null"]),
        "n_traffic_baseline_missing": sum(
            1 for r in rows if not r["traffic_baseline_weeks"]),
        "n_outage_event_features_missing": sum(
            1 for r in rows if not r["outage_has_event_features"]),
        "rows": rows,
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(out, indent=1, default=str))

    print(f"total {len(rows)}  light-mode {len(light)}  full-mode {len(full)}")
    print(f"expected_origin null on every hijack record: "
          f"{out['n_expected_origin_null_all']}")
    print(f"traffic baseline missing: {out['n_traffic_baseline_missing']}")
    print(f"outage event_features missing: "
          f"{out['n_outage_event_features_missing']}")
    print()
    print("class distribution:")
    for cls, slot in class_dist.items():
        print(f"  {cls:24s} n={slot['n']:2d}  light={slot['light']:2d}  "
              f"full={slot['full']:2d}")
    print()
    print("light-mode events:")
    for r in light:
        print(f"  {r['event_id']:42s} gt={r['gt_cause']:20s} "
              f"hijack_recs={r['hijack_records']:5d} "
              f"exp_null={r['expected_origin_null']:5d}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
