"""The leak detector's own confidence, per class.

The leak detector reports a ``leak_probability`` and a detection method
per record.  If the leak class were identifiable, its records would
carry systematically higher probability, or a systematically different
method, than the records the same detector emits for outage and hijack
events.  This script measures that directly.

It also measures the *path structure* of the leak records: a leak
announces the victim's prefix with the victim as the claiming origin
but reached over a path whose second-to-last hop is not the victim's
usual transit.  The detector's own ``detection_method`` and
``path_length`` are reported per class for the same reason.

Writes results/eval/leak_probability_report.json.
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
OUT_PATH = PROJECT_ROOT / "results" / "eval" / "leak_probability_report.json"
CLASSES = ("outage", "route_leak", "origin_hijack_victim")


def load_events() -> list[dict]:
    sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
    from component_ablation_gt import load_gt

    return load_gt()


def profile(routing: dict) -> dict:
    leaks = routing.get("route_leaks") or []
    probs = []
    methods: dict = {}
    lengths = []
    for rec in leaks:
        if not isinstance(rec, dict):
            continue
        evidence = rec.get("evidence") or {}
        p = evidence.get("leak_probability")
        if isinstance(p, (int, float)):
            probs.append(float(p))
        method = str(evidence.get("detection_method") or "")
        methods[method] = methods.get(method, 0) + 1
        length = evidence.get("path_length")
        if isinstance(length, (int, float)):
            lengths.append(int(length))
    probs.sort()
    return {
        "n_records": len(leaks),
        "n_with_probability": len(probs),
        "prob_median": round(probs[len(probs) // 2], 4) if probs else None,
        "prob_max": round(probs[-1], 4) if probs else None,
        "prob_mean": round(sum(probs) / len(probs), 4) if probs else None,
        "n_prob_above_threshold": sum(
            1 for p in probs if p >= 0.4),
        "methods": methods,
        "path_length_median": sorted(lengths)[len(lengths) // 2] if lengths else None,
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
        rows.append({
            "event_id": eid,
            "gt_cause": ev["gt_cause"],
            **profile(routing),
        })

    for cls in CLASSES:
        sub = [r for r in rows if r["gt_cause"] == cls]
        print(f"--- {cls} n={len(sub)}")
        for r in sorted(sub, key=lambda x: x["event_id"]):
            print(
                f"   {r['event_id']:40s} recs={r['n_records']:5d} "
                f"prob_med={str(r['prob_median']):>7s} prob_max={str(r['prob_max']):>7s} "
                f"above_thr={r['n_prob_above_threshold']:5d} "
                f"pathlen_med={str(r['path_length_median']):>4s} "
                f"methods={r['methods']}"
            )

    # Is any single threshold on the leak probability a class marker?
    print()
    best = None
    for thresh in (0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9):
        correct = 0
        for r in rows:
            pred_leak = (r["prob_median"] or 0.0) >= thresh
            actual_leak = r["gt_cause"] == "route_leak"
            if pred_leak == actual_leak:
                correct += 1
        if best is None or correct > best[1]:
            best = (thresh, correct)
        print(f"  median-prob threshold {thresh}: {correct}/{len(rows)}")
    print(f"  best: threshold {best[0]} -> {best[1]}/{len(rows)}")

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps({"rows": rows}, indent=1, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
