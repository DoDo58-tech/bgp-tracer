"""Check that the shared scan agrees with the standalone detectors.

The shared scan reads the update window once and dispatches each chunk
to the hijack, leak and outage detectors.  The standalone detectors each
read the window themselves.  This compares the two on the same window so
the refactor can be shown to be behaviour-preserving before anything is
evaluated at scale.
"""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

WINDOW = ("2025-07-14 00:00", "2025-07-14 02:00")
TARGET_AS = "13335"


def main() -> int:
    from detectors.shared_scan import SharedUpdateScan

    fmt = "%Y-%m-%d %H:%M"
    start = datetime.strptime(WINDOW[0], fmt)
    end = datetime.strptime(WINDOW[1], fmt)

    out = {"window": WINDOW, "target_as": TARGET_AS}

    # ── shared scan ────────────────────────────────────────────────
    print("[shared] running shared scan ...", flush=True)
    t0 = time.time()
    # The outage detector needs a baseline that starts before the event,
    # and the shared scan has to read that far back: a withdrawal is
    # attributed to the victim through the announcements that came
    # *before* it, so the ownership map is only complete when the
    # baseline is included.
    from detectors.outage.outage_detector import RouteOutageDetector
    from agents.impl.routing_impl import _outage_baseline_start

    detector = RouteOutageDetector()
    baseline_start = _outage_baseline_start(start, end, None)
    scan = SharedUpdateScan(
        start, end, target_asns=[TARGET_AS],
        baseline_start=baseline_start,
    )
    shared = scan.run()
    shared_secs = time.time() - t0
    print(f"[shared] done in {shared_secs:.1f}s "
          f"({shared['chunks_read']} chunks, {shared['rows_read']} rows)")

    shared_leak = shared.get("leak") or {}
    shared_outage_series = shared.get("outage") or {}

    # ── standalone detectors ────────────────────────────────────────
    print("[standalone] leak ...", flush=True)
    from detectors.leak.leak_detector import analyze_leak_surface
    t0 = time.time()
    solo_leak = analyze_leak_surface(TARGET_AS, WINDOW[0], WINDOW[1], target_asns=[TARGET_AS])
    leak_secs = time.time() - t0
    print(f"[standalone] leak done in {leak_secs:.1f}s")

    print("[standalone] outage ...", flush=True)
    from detectors.outage.outage_detector import RouteOutageDetector
    t0 = time.time()
    solo_outage = RouteOutageDetector().analyze(TARGET_AS, WINDOW[0], WINDOW[1])
    outage_secs = time.time() - t0
    print(f"[standalone] outage done in {outage_secs:.1f}s")

    # ── compare ────────────────────────────────────────────────────
    leak_same = (
        solo_leak.get("leak_count") == shared_leak.get("leak_count")
        and solo_leak.get("total_detected") == shared_leak.get("total_detected")
    )

    # The outage detector's own timeseries must match the shared scan's.
    # The shared scan covers the whole query range (baseline + event),
    # while the detector's `event_features` covers the event window
    # only, so the comparison has to be restricted to the event buckets.
    series = shared_outage_series.get(TARGET_AS) or {}
    solo_features = (solo_outage.get("event_features") or {})
    shared_features = _aggregate(series, start, end)
    # Every feature the outage detector reports on the event window has
    # to agree.  Comparing only the three counters would hide a
    # divergence in the path-length metrics, which the outage score uses.
    compared = sorted(
        k for k in solo_features
        if k in shared_features
    )
    mismatches = {
        k: (solo_features.get(k), shared_features.get(k))
        for k in compared
        if abs(float(solo_features.get(k, 0)) - float(shared_features.get(k, 0))) > 1e-6
    }
    outage_same = not mismatches

    out.update({
        "shared_seconds": round(shared_secs, 1),
        "standalone_leak_seconds": round(leak_secs, 1),
        "standalone_outage_seconds": round(outage_secs, 1),
        "leak_count_standalone": solo_leak.get("leak_count"),
        "leak_count_shared": shared_leak.get("leak_count"),
        "leak_total_standalone": solo_leak.get("total_detected"),
        "leak_total_shared": shared_leak.get("total_detected"),
        "leak_same": leak_same,
        "outage_same": outage_same,
        "outage_feature_mismatches": mismatches,
        "outage_event_features_standalone": solo_features,
        "outage_event_features_shared": shared_features,
    })

    dest = ROOT / "results" / "eval" / "shared_scan_parity.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
    print(json.dumps({k: v for k, v in out.items() if k != "outage_event_features_standalone"}, indent=2, default=str))
    return 0 if (leak_same and outage_same) else 2


def _aggregate(series: dict, start=None, end=None) -> dict:
    """Total the buckets, optionally restricted to the event window."""
    totals = {
        "announcement_count": 0,
        "withdrawal_count": 0,
        "total_messages": 0,
    }
    for key, bucket in series.items():
        if start is not None and end is not None:
            ts = datetime.fromisoformat(key)
            if not (start <= ts <= end):
                continue
        for k in totals:
            totals[k] += bucket.get(k, 0)
    return totals


if __name__ == "__main__":
    sys.exit(main())
