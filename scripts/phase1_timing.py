"""Measure where Phase-1 time goes, per detector, on one cached window.

Bounded: one window, one detector at a time, hard timeout each.  Writes
results/eval/phase1_timing.json.
"""
from __future__ import annotations

import json
import resource
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

EVENTS = {
    "cloudflare_dns": ("13335", "2025-07-14 00:00", "2025-07-14 02:00"),
    "hijack_30m": ("13335", "2024-06-27 18:51", "2024-06-27 19:21"),
    "leak_3h": ("17557", "2024-07-31 08:30", "2024-07-31 11:30"),
}


def timed(name, fn, timeout_s):
    t0 = time.perf_counter()
    rss0 = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    err = None
    out = None
    try:
        out = fn()
    except Exception as exc:  # noqa: BLE001
        err = f"{type(exc).__name__}: {exc}"
    el = time.perf_counter() - t0
    rss1 = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return {
        "stage": name,
        "elapsed_s": round(el, 2),
        "peak_rss_mb": round(rss1 / 1024, 1),
        "rss_delta_mb": round((rss1 - rss0) / 1024, 1),
        "error": err,
        "summary": out,
    }


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "cloudflare_dns"
    asn, start, end = EVENTS[which]
    rows = []

    def do_leak():
        from detectors.leak.leak_detector import analyze_leak_surface
        r = analyze_leak_surface(asn, start, end, target_asns=[asn])
        return {k: r.get(k) for k in ("success", "leak_count", "total_detected", "no_data_reason")}

    def do_hijack():
        from detectors.hijack.hijack_detector import detect_hijacks
        r = detect_hijacks(start, end, asn, validate_with_updates=False, skip_forge_detection=True)
        return {
            "success": r.get("success"),
            "origin_hijacked": len(r.get("origin_hijacked") or []),
            "origin_hijacking": len(r.get("origin_hijacking") or []),
        }

    def do_outage():
        from detectors.outage.outage_detector import RouteOutageDetector
        d = RouteOutageDetector()
        r = d.analyze(asn, start, end)
        return {k: r.get(k) for k in ("success", "outage_score", "is_outage_suspected", "no_data_reason")}

    for name, fn in (("leak", do_leak), ("hijack", do_hijack), ("outage", do_outage)):
        print(f"[phase1-timing] {which} {name} ...", flush=True)
        rows.append(timed(name, fn, 1800))

    out = ROOT / "results" / "eval" / "phase1_timing.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"event": which, "asn": asn, "start": start, "end": end,
                               "stages": rows}, indent=2), encoding="utf-8")
    print(json.dumps(rows, indent=2))


if __name__ == "__main__":
    main()
