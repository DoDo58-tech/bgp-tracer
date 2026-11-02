"""Rebuild the control-plane evidence for every corpus event, in parallel.

The evidence is the control plane's own record of the target's
announcements, and the scan is disk-bound rather than CPU-bound, so a
few workers saturate the disk without crowding the machine.
"""
from __future__ import annotations

import csv
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path("/data/bgp_tracer")
sys.path.insert(0, str(ROOT))

from agents.cache_resolution import resolve_cache
from agents.control_plane_archive import (
    BASELINE_DAYS,
    build_control_plane_evidence,
)
from agents.temporal import parse_timestamp

GT = ROOT / "data_check/ground_truth_collection/final_ground_truth.csv"
QUICK = ROOT / "results/quick"
EVIDENCE = ROOT / "results/eval/control_evidence"
WORKERS = 6


def unwrap(payload):
    if isinstance(payload, dict):
        for key in ("result", "data", "payload"):
            inner = payload.get(key)
            if isinstance(inner, dict) and inner:
                return inner
    return payload if isinstance(payload, dict) else {}


def scan_window(cache, event):
    traffic = unwrap(cache.get("traffic"))
    window = traffic.get("consecutive_anomaly_windows") or []
    if not window and isinstance(traffic.get("expanded_windows"), list):
        window = traffic["expanded_windows"]
    bounds = [parse_timestamp(event.get("start_utc")),
              parse_timestamp(event.get("end_utc"))]
    for item in window:
        if isinstance(item, dict):
            bounds.append(parse_timestamp(item.get("start")))
            bounds.append(parse_timestamp(item.get("end")))
    bounds = [b for b in bounds if b is not None]
    if not bounds:
        return None, None
    return min(bounds), max(bounds)


def one(event):
    event_id = event.get("event_id") or ""
    asn = str(event.get("victim_as") or event.get("target_as") or "")
    match = resolve_cache(asn, event.get("start_utc"), event.get("end_utc"),
                          QUICK, event_id=event_id, allow_same_date=False)
    if match is None:
        return event_id, "no_cache", None
    cache = json.loads(match.path.read_text(encoding="utf-8"))
    lo, hi = scan_window(cache, event)
    if lo is None:
        return event_id, "no_window", None

    path = EVIDENCE / f"{asn}_{lo:%Y%m%d%H%M}_{hi:%Y%m%d%H%M}.json"
    if path.is_file():
        age_h = (time.time() - path.stat().st_mtime) / 3600
        if age_h < 3:
            return event_id, "fresh", path

    started = time.time()
    evidence = build_control_plane_evidence(asn, lo, hi)
    payload = evidence.to_payload()
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return event_id, f"built in {time.time()-started:.0f}s", path


def main():
    events = list(csv.DictReader(open(GT, encoding="utf-8")))
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for event_id, status, _ in pool.map(one, events):
            print(f"{event_id:52s} {status}", flush=True)
    print("done")


if __name__ == "__main__":
    main()
