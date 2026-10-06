#!/usr/bin/env python
"""Per-event detector-vs-report consistency check.

For every row in the canonical v16 CSV, look at the project's own quick-cache
results and report what the detector actually saw for that AS/window. The goal
is to answer the user's question: does the detector detect anomalies consistent
with the public report?

This script is read-only: it never edits rows and never reads detector output
to decide ground-truth inclusion. Inclusion is decided by the seed list.

Inputs
------
- final_balanced_dataset_v16.csv  (the canonical dataset)
- results/quick/quick_*.json      (detector output per event)

Output
------
- results/v16_detector_consistency.csv : per-row detector signals
- results/v16_detector_consistency.json: aggregate counts
"""
from __future__ import annotations

import csv
import glob
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CSV = ROOT / "data_check" / "ground_truth_collection" / "final_balanced_dataset_v16.csv"
QUICK = ROOT / "results" / "quick"
OUT_CSV = ROOT / "results" / "v16_detector_consistency.csv"
OUT_JSON = ROOT / "results" / "v16_detector_consistency.json"


def norm_asn(value: str) -> str:
    s = str(value or "").upper().replace("AS", "").strip()
    return s if s.isdigit() else ""


def parse_dt(value: str):
    if not value:
        return None
    text = str(value).strip().replace("T", " ").rstrip("Z")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            from datetime import datetime as _dt
            return _dt.strptime(text, fmt)
        except ValueError:
            continue
    return None


def parse_iso_dt(value: str):
    if not value:
        return None
    from datetime import datetime as _dt
    text = str(value).strip().replace("T", " ").rstrip("Z")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M",
                "%Y-%m-%d"):
        try:
            return _dt.strptime(text, fmt)
        except ValueError:
            continue
    return None


def asn_in_path(asn_digits: str, path_str: str) -> bool:
    if not asn_digits or not path_str:
        return False
    return re.search(rf"(^| ){asn_digits}( |$)", str(path_str)) is not None


def pick_quick(asn: str, start_iso: str, end_iso: str) -> list[dict]:
    """Find every quick-cache JSON whose event matches the v16 row exactly.

    Cache filenames come in two flavours:

      quick_<asn>_<start>_<end>.json
      quick_<asn>_<datetime>T<datetime>.json   (missing-tz variant)

    We accept caches whose recorded start/end are within ±5 min of the CSV
    row. Wider tolerances would let through re-runs of the same event with
    different windows; tighter would miss legitimate ±10 min operator wiggle.
    """
    if not asn:
        return []
    target_asn = str(asn)
    target_start = parse_iso_dt(start_iso)
    target_end = parse_iso_dt(end_iso)
    out = []
    for path in QUICK.iterdir():
        if not path.name.startswith(f"quick_{target_asn}_"):
            continue
        if not path.name.endswith(".json"):
            continue
        try:
            with path.open() as fh:
                rec = json.load(fh)
        except Exception:
            continue
        cstart = parse_iso_dt(rec.get("start_time", ""))
        cend = parse_iso_dt(rec.get("end_time", ""))
        if cstart is None or cend is None:
            continue
        if abs((cstart - target_start).total_seconds()) > 300:
            continue
        if abs((cend - target_end).total_seconds()) > 300:
            continue
        out.append(rec)
    return out


def audit_row(row: dict) -> dict:
    """Per-event detector audit.

    Returns a dict with:
      routing_seen          number of routing anomalies in window
      routing_top_origin    top origin AS by count (or '')
      routing_has_attacker  True if the reported attacker AS appears as origin
                            or in the path of any routing event in window
      routing_has_victim    True if victim AS is an origin in window
      traffic_anomaly_min   minimum z-score within window
      traffic_anomaly_max   maximum z-score within window
      detector_event_kind   detector's verdict ("hijack"/"leak"/"outage"/...)
      caches_found          number of matching quick caches
    """
    victim = norm_asn(row.get("victim_as"))
    attacker = norm_asn(row.get("attacker_as"))
    leaker = norm_asn(row.get("leak_as"))
    target = victim or leaker

    caches = pick_quick(target, row.get("start_time_utc", ""),
                        row.get("end_time_utc", ""))
    if not caches:
        return {
            "event_id": row.get("event_id"),
            "caches_found": 0,
            "detector_event_kind": "",
            "routing_seen": 0,
            "routing_top_origin": "",
            "routing_has_attacker": False,
            "routing_has_victim": False,
            "traffic_anomaly_min": "",
            "traffic_anomaly_max": "",
        }

    routing = []
    traffic = []
    detector_kind = ""
    for rec in caches:
        detector_kind = detector_kind or (rec.get("event", {}).get("kind", "") or "")
        corr = rec.get("correlation", {})
        routing.extend(corr.get("routing_events", []) or [])
        traffic.extend(corr.get("traffic_events", []) or [])

    # Identify synthetic / placeholder routing events. The project's own
    # bug tracker names these; they look like real routing events but carry
    # payload.note == "synthetic routing event for ...". They are NOT real
    # detections and must be excluded from the routing_seen count.
    real_routing = [r for r in routing
                    if not str(r.get("payload", {}).get("note", "")).startswith("synthetic")]

    has_attacker = False
    has_victim_origin = False
    origin_counts: dict[str, int] = {}
    for r in real_routing:
        asn_field = str(r.get("asn", ""))
        payload = r.get("payload", {}) or {}
        origin_as = str(payload.get("origin_as") or payload.get("origin") or asn_field)
        origin_counts[origin_as] = origin_counts.get(origin_as, 0) + 1
        path_str = str(payload.get("as_path") or payload.get("path") or "")
        if attacker and (origin_as == attacker or asn_in_path(attacker, path_str)):
            has_attacker = True
        if victim and origin_as == victim:
            has_victim_origin = True

    top_origin = ""
    if origin_counts:
        top_origin = max(origin_counts.items(), key=lambda kv: kv[1])[0]

    z_scores = []
    for t in traffic:
        z = t.get("z_score")
        if z is None:
            continue
        try:
            z_scores.append(float(z))
        except (TypeError, ValueError):
            continue

    return {
        "event_id": row.get("event_id"),
        "caches_found": len(caches),
        "detector_event_kind": detector_kind,
        "routing_seen": len(real_routing),
        "routing_top_origin": top_origin,
        "routing_has_attacker": has_attacker,
        "routing_has_victim": has_victim_origin,
        "traffic_anomaly_min": (min(z_scores) if z_scores else ""),
        "traffic_anomaly_max": (max(z_scores) if z_scores else ""),
    }


def main():
    with CSV.open(newline="", encoding="utf-8-sig") as fh:
        rows = list(csv.DictReader(fh))

    audited = [audit_row(r) for r in rows]

    fields = [
        "event_id", "caches_found", "detector_event_kind", "routing_seen",
        "routing_top_origin", "routing_has_attacker", "routing_has_victim",
        "traffic_anomaly_min", "traffic_anomaly_max",
    ]
    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with OUT_CSV.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(audited)

    total = len(audited)
    no_cache = sum(1 for a in audited if a["caches_found"] == 0)
    has_routing = sum(1 for a in audited if a["routing_seen"] > 0)
    has_attacker = sum(1 for a in audited if a["routing_has_attacker"])
    has_victim = sum(1 for a in audited if a["routing_has_victim"])
    has_traffic_z = sum(1 for a in audited if a["traffic_anomaly_max"] != "")

    summary = {
        "total_events": total,
        "no_quick_cache": no_cache,
        "detector_found_routing_event": has_routing,
        "detector_sees_reported_attacker_or_leaker": has_attacker,
        "detector_sees_reported_victim_origin": has_victim,
        "detector_has_traffic_z_score": has_traffic_z,
    }
    OUT_JSON.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(f"Total events in v16: {total}")
    print(f"  quick cache missing (no detector run): {no_cache}")
    print(f"  detector flagged ≥1 routing event in window: {has_routing}")
    print(f"  detector saw reported attacker/leaker AS: {has_attacker}")
    print(f"  detector saw reported victim as origin: {has_victim}")
    print(f"  detector saw measurable traffic z-score: {has_traffic_z}")
    print()
    print(f"Per-event table written to: {OUT_CSV.relative_to(ROOT)}")
    print(f"Summary written to: {OUT_JSON.relative_to(ROOT)}")


if __name__ == "__main__":
    sys.exit(main())