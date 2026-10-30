"""Diagnose why AEA abstains on the labelled corpus.

Prints, for every event with a usable cache: the two bucket series as the
production path builds them, the segmentation the estimator sees, and the
first veto that refuses.  The point is to find out whether the refusals come
from the estimator's decision rule or from the *representation* of the
evidence it is handed.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents._segmentation import detect_changes, onset_interval  # noqa: E402
from agents.aea_runtime import build_shared_series, parse_timestamp  # noqa: E402
from agents.edge_ownership import AEA_PROTOCOL, attribute  # noqa: E402

QUICK = ROOT / "results/quick"


def find_caches() -> list[Path]:
    out = []
    for p in sorted(QUICK.rglob("*.json")):
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        corr = d.get("correlation") or {}
        if isinstance(corr, dict) and (corr.get("routing_events_full")
                                        or corr.get("timeline")):
            out.append(p)
    return out


def production_timelines(cache: Path):
    """Build the two timelines the way workflow_engine does."""
    data = json.loads(cache.read_text(encoding="utf-8"))
    corr = data.get("correlation") or {}
    routing: list[dict] = []
    traffic: list[dict] = []
    events = []
    for key in ("routing_events_full", "traffic_events_full"):
        block = corr.get(key)
        if isinstance(block, list):
            events.extend(block)
    if not events:
        events = list(corr.get("timeline") or [])
    for ev in events:
        if not isinstance(ev, dict):
            continue
        ts = ev.get("timestamp") or ev.get("first_seen")
        if not ts:
            continue
        score = float(ev.get("score", 0.0) or 0.0)
        et = str(ev.get("event_type") or ev.get("type") or "")
        if "routing" in et or ev.get("as_path") is not None:
            routing.append({"timestamp": ts, "score": score, "event_type": et})
        else:
            traffic.append({"timestamp": ts, "score": score, "event_type": et})
    return routing, traffic, data


def main() -> int:
    cfg = AEA_PROTOCOL
    caches = find_caches()
    print(f"caches with correlation evidence: {len(caches)}\n")
    shown = 0
    for cache in caches:
        routing, traffic, data = production_timelines(cache)
        if not routing or not traffic:
            continue
        start = parse_timestamp(data.get("start_time"))
        end = parse_timestamp(data.get("end_time"))
        r, t = build_shared_series(routing, traffic, start, end)
        if len(r) < 3:
            continue
        v = attribute(r, t)
        min_seg = max(2, int(round(cfg["min_segment_frac"] * len(r))))
        dr = detect_changes(np.array(r), min_seg, cfg["bic_penalty"])
        dt = detect_changes(np.array(t), min_seg, cfg["bic_penalty"])
        print(f"=== {cache.name} ===")
        print(f"  window={data.get('start_time')} .. {data.get('end_time')}")
        print(f"  buckets={len(r)} routing_pts={len(routing)} traffic_pts={len(traffic)}")
        print(f"  routing seg: model={dr['model']} changes={dr['changes']} "
              f"t_onset={dr['t_onset']:.2f} means={[round(m,3) for m in dr['means']]}")
        print(f"  traffic seg: model={dt['model']} changes={dt['changes']} "
              f"t_onset={dt['t_onset']:.2f} means={[round(m,3) for m in dt['means']]}")
        print(f"  routing series: {[round(x,2) for x in r]}")
        print(f"  traffic series: {[round(x,2) for x in t]}")
        print(f"  VERDICT direction={v.direction} reason={v.reason} vetoes={v.vetoes}")
        print()
        shown += 1
        if shown >= 6:
            break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
