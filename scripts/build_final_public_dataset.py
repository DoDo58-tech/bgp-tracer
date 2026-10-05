#!/usr/bin/env python
"""Build the final ground-truth dataset from publicly reported events only.

This script is deliberately *destructive-by-filtering*, not generative. It never
invents an event and never promotes an unverified alert into ground truth. The
only thing it produces is the subset of an existing dataset that satisfies two
hard requirements:

  1. Provenance: the event must be traceable to public reporting (news, vendor
     or network-operator blog, NANOG, APNIC/RIPE, Cloudflare postmortem, IODA,
     an operator status page, a published paper). Anything whose only source is
     a BGPStream alert ID is dropped.
  2. Runnability: every retained event needs a resolvable AS and a real
     start/end time, because the detectors cannot be run without them.

Detectability is NOT an input to inclusion. Whether the detector currently
flags an event is *measured* by `scripts/scan_public_events.py` and recorded in
the `measured_*` columns, so that a detector miss is visible as a miss rather
than hidden by deleting the row. Selecting events by detector output would be
the exact leakage the project forbids.

Usage
-----
    python scripts/build_final_public_dataset.py
    python scripts/build_final_public_dataset.py --scan   # also re-measure
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COLLECT = ROOT / "data_check" / "ground_truth_collection"
SRC = COLLECT / "final_balanced_dataset_v13.csv"
OUT = COLLECT / "final_public_dataset.csv"
DROPPED = COLLECT / "final_public_dataset_dropped.csv"
SCAN_JSON = ROOT / "results" / "scan_public.json"

# Substrings that mark a row as sourced from a raw alerting platform rather than
# from public reporting. Matched case-insensitively against the provenance text
# and the source URL.
ALERT_PLATFORM_MARKERS = ("bgpstream",)

# Columns carried through unchanged from the source dataset.
KEEP_COLUMNS = [
    "tier", "event_id", "name", "date", "start_time_utc", "end_time_utc",
    "duration_hours", "victim_as", "attacker_as", "leak_as", "event_type",
    "ground_truth_cause_label", "ground_truth_root_cause_subtype",
    "ground_truth_confidence", "routing_evidence_source",
    "routing_origin_count", "routing_withdrawal_count",
    "ground_truth_source", "source_url", "rrc00_covered", "notes",
]

# Columns appended by this script.
MEASURED_COLUMNS = [
    "measured_anomaly_count", "measured_detected", "measured_peak_trough_drop_pct",
    "measured_data_points", "measured_scan_status",
]


def is_alert_platform(row: dict) -> bool:
    blob = f"{row.get('ground_truth_source', '')} {row.get('source_url', '')}".lower()
    return any(m in blob for m in ALERT_PLATFORM_MARKERS)


def target_asn(row: dict) -> str:
    for key in ("victim_as", "leak_as", "attacker_as"):
        val = (row.get(key) or "").strip()
        if val:
            return val
    return ""


def load_scan(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {r["event_id"]: r for r in data if r.get("event_id")}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scan", action="store_true",
                    help="re-run the detector scan before writing (slow)")
    args = ap.parse_args()

    if args.scan:
        import subprocess
        subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "scan_public_events.py"),
             "--out", str(SCAN_JSON)],
            check=True, cwd=ROOT,
        )

    with SRC.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        source_rows = list(reader)
        src_fields = list(reader.fieldnames or [])

    scan = load_scan(SCAN_JSON)

    kept, dropped = [], []
    for row in source_rows:
        eid = row.get("event_id", "")
        if is_alert_platform(row):
            dropped.append({**row,
                            "drop_reason": "alert_platform_only_source",
                            "drop_detail": (row.get("ground_truth_source", "") or "")[:120]})
            continue

        # A row without an AS or without a time window cannot be detected, so
        # it cannot serve as ground truth either. Drop it with a reason rather
        # than shipping a row that silently no-ops.
        if not target_asn(row):
            dropped.append({**row, "drop_reason": "no_target_as",
                            "drop_detail": "victim_as/leak_as/attacker_as all empty"})
            continue
        if not (row.get("start_time_utc") or "").strip() or not (row.get("end_time_utc") or "").strip():
            dropped.append({**row, "drop_reason": "missing_time_window",
                            "drop_detail": "start_time_utc/end_time_utc empty"})
            continue

        m = scan.get(eid, {})
        new = {c: row.get(c, "") for c in KEEP_COLUMNS}
        new["measured_anomaly_count"] = m.get("anomaly_count", "")
        new["measured_detected"] = ("true" if m.get("anomaly_count")
                                    else ("false" if m.get("scanned") else ""))
        new["measured_peak_trough_drop_pct"] = m.get("peak_trough_drop_pct", "")
        new["measured_data_points"] = m.get("data_points", "")
        if not m:
            new["measured_scan_status"] = "not_measured"
        elif m.get("scanned"):
            new["measured_scan_status"] = "ok"
        else:
            new["measured_scan_status"] = m.get("error", "")[:60]
        kept.append(new)

    fields = KEEP_COLUMNS + MEASURED_COLUMNS
    with OUT.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(kept)

    drop_fields = [c for c in src_fields if c not in KEEP_COLUMNS] + \
                  ["drop_reason", "drop_detail"]
    with DROPPED.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=drop_fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(dropped)

    measured = [r for r in kept if r["measured_detected"] != ""]
    hits = [r for r in measured if r["measured_detected"] == "true"]
    print(f"source rows       : {len(source_rows)}")
    print(f"kept (public)     : {len(kept)}  -> {OUT.relative_to(ROOT)}")
    print(f"dropped           : {len(dropped)} -> {DROPPED.relative_to(ROOT)}")
    print(f"measured          : {len(hits)}/{len(measured)} detected")
    unmeasured = [r["event_id"] for r in kept if r["measured_detected"] == ""]
    if unmeasured:
        print(f"not measured      : {', '.join(unmeasured)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
