#!/usr/bin/env python3
"""
Build quick caches for the v18 candidate events using the existing
cache_with_download.py logic. Runs up to N events in parallel.

Usage:
    python3 scripts/build_v18_caches.py \
        --candidates data_check/ground_truth_collection/v18_candidates.jsonl \
        --out data_check/ground_truth_collection/v18_caches.jsonl \
        --max-workers 4
"""
from __future__ import annotations
import argparse
import json
import os
import sys
import time
import traceback
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("BGPT_RUN_LEAK", "1")
os.environ.setdefault("BGPT_RUN_OUTAGE", "0")


def _build_one(event: dict) -> dict:
    """Run cache_for_event for one event. Returns dict with event_id + result."""
    eid = event.get("event_id", "?")
    out: dict = {"event_id": eid, "asn": event["asn"],
                 "start": event["start"], "end": event["end"]}
    t0 = time.time()
    try:
        # Import here to avoid loading the heavy modules in the parent
        from scripts.cache_with_download import cache_for_event
        res = cache_for_event(
            event["asn"], event["start"], event["end"],
            skip_download=False,
            run_leak=True,
            run_outage=False,
        )
        out.update(res)
    except Exception as e:
        out["error"] = repr(e)
        out["traceback"] = traceback.format_exc()[:1000]
    out["wall_clock_s"] = round(time.time() - t0, 1)
    return out


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--candidates", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--max-workers", type=int, default=4)
    p.add_argument("--limit", type=int, default=0, help="Limit to first N events (debug)")
    p.add_argument("--skip-download", action="store_true",
                   help="Don't try to download from RIPE RIS")
    args = p.parse_args()

    events = [json.loads(l) for l in args.candidates.open() if l.strip()]
    if args.limit:
        events = events[:args.limit]
    print(f"Loaded {len(events)} candidate events")
    print(f"Building caches with up to {args.max_workers} parallel workers")
    print(f"Output: {args.out}")
    print()

    args.out.parent.mkdir(parents=True, exist_ok=True)
    if args.out.exists():
        args.out.unlink()

    started = datetime.now().isoformat(timespec="seconds")
    with args.out.open("w") as fout:
        fout.write(f"# started={started} workers={args.max_workers}\n")
        if args.max_workers <= 1:
            for ev in events:
                print(f"\n=== {ev['event_id']} AS{ev['asn']} {ev['start']} → {ev['end']} ===", flush=True)
                r = _build_one(ev)
                print(f"  → {r.get('event_id')}  elapsed={r.get('wall_clock_s', 0)}s  "
                      f"success={r.get('success')}  n_leaks={r.get('n_route_leaks', 0)}  "
                      f"traffic={r.get('traffic_signal_present')}  err={r.get('error', '')[:60]}",
                      flush=True)
                fout.write(json.dumps(r, ensure_ascii=False) + "\n")
                fout.flush()
        else:
            with ProcessPoolExecutor(max_workers=args.max_workers) as ex:
                futures = {ex.submit(_build_one, ev): ev for ev in events}
                for fut in as_completed(futures):
                    ev = futures[fut]
                    try:
                        r = fut.result()
                    except Exception as e:
                        r = {"event_id": ev.get("event_id", "?"), "error": repr(e)}
                    print(f"  → {r.get('event_id')}  elapsed={r.get('wall_clock_s', 0)}s  "
                          f"success={r.get('success')}  n_leaks={r.get('n_route_leaks', 0)}  "
                          f"traffic={r.get('traffic_signal_present')}  err={r.get('error', '')[:60]}",
                          flush=True)
                    fout.write(json.dumps(r, ensure_ascii=False) + "\n")
                    fout.flush()
    print(f"\nWrote {args.out}")


if __name__ == "__main__":
    main()
