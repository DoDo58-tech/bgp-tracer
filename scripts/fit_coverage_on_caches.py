"""Measure FIT coverage on the archived quick caches (labels not needed)."""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.cache_resolution import (  # noqa: E402
    infer_hour_offset,
    parse_datetime,
)
from agents.falsification_test import (  # noqa: E402
    PROTOCOL,
    UNKNOWN,
    infer_direction,
)
from scripts.eval_hcaf_vs_baselines import split_merged_timeline  # noqa: E402


def series_for(cache: Path, repair: str = "none"):
    """Build the two bucket series for one cache.
    
    Returns ``(routing, traffic, reason, offset_hours)``.  ``repair='auto'``
    enables the whole-hour alignment described in
    :func:`agents.cache_resolution.infer_hour_offset`; the applied offset is
    returned so the caller can count how much of the corpus needed it."""
    data = json.loads(cache.read_text(encoding="utf-8"))
    corr = data.get("correlation", {}) or {}
    events: List[dict] = []
    for key in ("routing_events_full", "traffic_events_full"):
        block = corr.get(key)
        if isinstance(block, list):
            events.extend(block)
    if not events:
        events = list(corr.get("timeline") or [])
    start = parse_datetime(data.get("start_time"))
    end = parse_datetime(data.get("end_time"))
    if start is None or end is None or end <= start:
        # A cache without a window cannot be bucketed honestly.
        return None, None, "no_window", 0
    events.sort(key=lambda e: str(e.get("timestamp", "")))
    offset = 0
    if repair == "auto":
        offset = infer_hour_offset(
            [parse_datetime(e.get("timestamp")) for e in events], start, end)
    routing, traffic = split_merged_timeline(
        events, window_start=start, window_end=end, repair_offset=offset)
    if not routing or not traffic:
        return None, None, "no_events_in_window", offset
    r = np.array([float(p.get("score", 0.0)) for p in routing])
    t = np.array([float(p.get("score", 0.0)) for p in traffic])
    if r.max() <= 1e-6:
        return r, t, "empty_routing_buckets", offset
    if t.max() <= 1e-6:
        return r, t, "empty_traffic_buckets", offset
    return r, t, "", offset


def measure(caches: List[Path], repair: str) -> Dict[str, Any]:
    reasons: Counter = Counter()
    offsets: Counter = Counter()
    committed = 0
    scored = 0
    buckets: List[int] = []
    examples: List[Dict[str, Any]] = []

    for cache in caches:
        r, t, pre_reason, offset = series_for(cache, repair)
        if offset:
            offsets[offset] += 1
        if pre_reason:
            reasons[pre_reason] += 1
            continue
        scored += 1
        buckets.append(int(min(len(r), len(t))))
        res = infer_direction(r, t)
        reasons[res.reason] += 1
        if res.direction != UNKNOWN:
            committed += 1
            if len(examples) < 10:
                examples.append({
                    "cache": cache.name,
                    "direction": res.direction,
                    "lag": res.lag,
                    "p_value": res.p_value,
                    "n_buckets": int(min(len(r), len(t))),
                    "offset_hours": offset,
                })

    return {
        "repair": repair,
        "n_series_built": scored,
        "n_committed": committed,
        "coverage": round(committed / scored, 4) if scored else 0.0,
        "reasons": dict(reasons.most_common()),
        "offsets_applied": {str(k): v for k, v in offsets.most_common()},
        "n_buckets": {
            "min": int(min(buckets)) if buckets else None,
            "median": float(np.median(buckets)) if buckets else None,
            "max": int(max(buckets)) if buckets else None,
        },
        "committed_examples": examples,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick-dir", default=str(ROOT / "results/quick"))
    ap.add_argument("--out", default=str(ROOT / "results/eval/fit_coverage_caches.json"))
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    quick = Path(args.quick_dir)
    caches = sorted(quick.glob("quick_*.json"))
    if args.limit:
        caches = caches[: args.limit]

    runs = [measure(caches, "none"), measure(caches, "auto")]
    out = {"protocol": PROTOCOL, "n_caches": len(caches), "runs": runs}
    path = Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")

    print(f"caches: {len(caches)}")
    for run in runs:
        print(f"\n[repair={run['repair']}]  series built: "
              f"{run['n_series_built']}   committed: {run['n_committed']}")
        if run["n_buckets"]["min"] is not None:
            print(f"  buckets: min={run['n_buckets']['min']} "
                  f"median={run['n_buckets']['median']:.0f} "
                  f"max={run['n_buckets']['max']}")
        if run["offsets_applied"]:
            print(f"  offsets applied (hours -> caches): {run['offsets_applied']}")
        for reason, count in run["reasons"].items():
            print(f"  {reason:<26}{count:>5}")
    print(f"\nwrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())