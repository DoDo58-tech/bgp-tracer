"""Where does the Phase-1 time go?

The Phase-1 pipeline reads the same BGP buckets once per detector, so
the cost of a run is dominated by how many times the update stream is
scanned.  This script measures that directly: it times each stage of
a Phase-1 run on one cached window and reports the split.

The result decides whether the efficiency work belongs in the leak
detector (which reads every announcement and scores every AS path) or
in the hijack/outage detectors (which also read the stream).

Writes results/eval/phase1_profile.json.
"""
from __future__ import annotations

import csv
import json
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.cache_resolution import resolve_cache  # noqa: E402

GT_CSV = PROJECT_ROOT / "data_check" / "ground_truth_collection" / "final_ground_truth.csv"
QUICK_DIR = PROJECT_ROOT / "results" / "quick"
OUT_PATH = PROJECT_ROOT / "results" / "eval" / "phase1_profile.json"

# One event from each class, so the profile is not a single-path
# anecdote.
SAMPLE_EVENTS = (
    "leak_as4808_mar_2025",
    "outage_honduras_2025_03_01",
    "hijack_cloudflare_1.1.1.1_2024",
)


def load_gt() -> dict:
    out = {}
    for r in csv.DictReader(GT_CSV.open()):
        out[r["event_id"]] = {
            "asn": str(r.get("victim_as") or "").replace("AS", "").strip(),
            "start": (r.get("start_utc") or "").strip(),
            "end": (r.get("end_utc") or "").strip(),
        }
    return out


def time_call(fn, *args, **kwargs):
    t0 = time.perf_counter()
    try:
        value = fn(*args, **kwargs)
        error = None
    except Exception as exc:  # noqa: BLE001
        value = None
        error = f"{type(exc).__name__}: {exc}"
    return round(time.perf_counter() - t0, 2), value, error


def main() -> int:
    events = load_gt()
    from detectors.leak.leak_detector import analyze_leak_surface
    from detectors.hijack.hijack_detector import detect_hijacks
    from detectors.outage.outage_detector import RouteOutageDetector

    rows = []
    for eid in SAMPLE_EVENTS:
        ev = events.get(eid)
        if not ev:
            continue
        match = resolve_cache(ev["asn"], ev["start"], ev["end"], QUICK_DIR)
        if not match or not match.path.exists():
            continue

        leak_s, leak_v, leak_err = time_call(
            analyze_leak_surface, ev["asn"], ev["start"], ev["end"],
            target_asns=[ev["asn"]],
        )
        hijack_s, hijack_v, hijack_err = time_call(
            detect_hijacks, ev["start"], ev["end"], ev["asn"],
            validate_with_updates=False, skip_forge_detection=True,
        )
        outage_s, outage_v, outage_err = time_call(
            RouteOutageDetector().analyze, ev["asn"], ev["start"], ev["end"],
        )

        row = {
            "event_id": eid,
            "asn": ev["asn"],
            "window": f"{ev['start']} -> {ev['end']}",
            "leak_seconds": leak_s,
            "leak_error": leak_err,
            "leak_records": (leak_v or {}).get("leak_count") if isinstance(leak_v, dict) else None,
            "leak_announcements_scanned": (
                (leak_v or {}).get("total_announcements")
                if isinstance(leak_v, dict) else None
            ),
            "hijack_seconds": hijack_s,
            "hijack_error": hijack_err,
            "hijack_records": (
                len((hijack_v or {}).get("origin_hijacked") or [])
                if isinstance(hijack_v, dict) else None
            ),
            "outage_seconds": outage_s,
            "outage_error": outage_err,
        }
        row["total_seconds"] = round(
            leak_s + hijack_s + outage_s, 2
        )
        rows.append(row)
        print(
            f"{eid:42s} leak={leak_s:8.1f}s "
            f"hijack={hijack_s:8.1f}s outage={outage_s:8.1f}s "
            f"total={row['total_seconds']:8.1f}s",
            flush=True,
        )

    OUT_PATH.write_text(json.dumps(rows, indent=1, default=str))
    if rows:
        print()
        for key, label in (("leak_seconds", "leak"),
                           ("hijack_seconds", "hijack"),
                           ("outage_seconds", "outage")):
            total = sum(r[key] for r in rows)
            print(f"{label:10s} total {total:8.1f}s  "
                  f"share {total / sum(r['total_seconds'] for r in rows):.1%}")
    print(f"\nwrote {OUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
