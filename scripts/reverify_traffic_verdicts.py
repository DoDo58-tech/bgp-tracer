#!/usr/bin/env python3
"""Re-decide the traffic verdicts from the stored measurements.

The routing and traffic measurements are journalled per event, so a
change to the *verdict logic* does not require re-reading the BGP
stream or re-querying Radar.  This script replays the stored
measurements through the current verdict function and rewrites the
accepted and rejected lists.

Only the verdict is recomputed.  The measurements themselves -- the
z-score, the drop, the control -- are taken from the journal exactly
as they were measured, so a re-run cannot silently change a number.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from detectors.gt_verify.traffic_signal import TrafficMeasurement  # noqa: E402
from detectors.gt_verify.traffic_signal import verdict as traffic_verdict  # noqa: E402

GT_DIR = ROOT / "data_check" / "ground_truth_collection"
JOURNAL = GT_DIR / "_verification_journal.jsonl"
OUT_CSV = GT_DIR / "final_ground_truth.csv"
REJECTED_CSV = GT_DIR / "final_ground_truth_rejected.csv"
REPORT = GT_DIR / "final_ground_truth_build.json"

CAUSES = ("outage", "route_leak", "origin_hijack_victim")


def measurement_from_record(detail: dict) -> TrafficMeasurement:
    """Rebuild a measurement from its journalled form."""
    m = TrafficMeasurement()
    m.event_id = detail.get("event_id", "")
    m.scope = detail.get("traffic_scope", "")
    m.series_id = detail.get("traffic_series_id", "")
    m.n_window = int(detail.get("traffic_n_window", 0) or 0)
    m.n_event = int(detail.get("traffic_n_event", 0) or 0)
    m.n_baseline = int(detail.get("traffic_n_baseline", 0) or 0)
    m.z_min = float(detail.get("traffic_z_min", 0.0) or 0.0)
    m.pct_drop = float(detail.get("traffic_pct_drop", 0.0) or 0.0)
    m.control_z_min = float(detail.get("traffic_control_z_min", 0.0) or 0.0)
    m.control_pct_drop = float(detail.get("traffic_control_pct_drop", 0.0) or 0.0)
    m.trough_time = detail.get("traffic_trough_time", "")
    m.trough_in_event = bool(detail.get("traffic_trough_in_event", False))
    m.error = detail.get("traffic_error", "")
    m.no_data_reason = detail.get("traffic_no_data_reason", "")
    return m


def recompute_trough(detail: dict, start, end) -> bool:
    """Whether the measured trough sits inside the compared window.

    The journal stores the trough *time*, so the "is it near the event"
    question can be answered again without re-querying Radar -- and it
    has to be, because the answer depends on a rule that can change.

    The window is the padded one, the same window the measurement was
    taken over: Radar's sample timestamps do not line up exactly with
    the incident times in the public reports.
    """
    from detectors.gt_verify.traffic_signal import (
        EVENT_LEAD,
        EVENT_TAIL,
        _within,
    )
    return _within(
        detail.get("traffic_trough_time", ""),
        start - EVENT_LEAD,
        end + EVENT_TAIL,
    )


def main() -> int:
    if not JOURNAL.is_file():
        print(f"no journal at {JOURNAL}")
        return 1

    # The pool holds the metadata of every candidate event.
    pool = json.loads((GT_DIR / "_pool.json").read_text(encoding="utf-8"))
    pool_rows = {row["event_id"]: row for row in pool}

    entries = []
    for line in JOURNAL.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            entries.append(json.loads(line))
        except ValueError:
            continue

    changed = 0
    for entry in entries:
        record = entry.get("record") or {}
        detail = record.get("traffic_detail")
        control = record.get("control")
        if not detail or not control:
            continue

        measurement = measurement_from_record(detail)
        # The "is the trough near the event" answer depends on a rule
        # that can change, so it is recomputed from the stored trough
        # time rather than trusted from the journal.
        pool_row = pool_rows.get(entry["event_id"], {})
        start = parse_ts(pool_row.get("start_utc") or pool_row.get("start_time_utc", ""))
        end = parse_ts(pool_row.get("end_utc") or pool_row.get("end_time_utc", ""))
        if start is not None and end is not None:
            measurement.trough_in_event = recompute_trough(detail, start, end)

        old = (record.get("traffic") or {}).get("traffic_impact")
        new = traffic_verdict(
            measurement,
            float(control.get("z_min", 0.0) or 0.0),
            float(control.get("pct_drop", 0.0) or 0.0),
        )
        if new["traffic_impact"] != old:
            changed += 1
            print(f"  {entry['event_id']}: {old} -> {new['traffic_impact']}")
        record["traffic"] = new
        entry["record"] = record

        if new["traffic_impact"] != "yes" and entry.get("accepted"):
            entry["accepted"] = None
            entry["rejected"] = {
                "event_id": entry["event_id"],
                "cause": (record.get("cause") or "").strip(),
                "reason": (
                    f"traffic_impact_not_confirmed({new.get('traffic_note', '')})"
                ),
            }
        elif new["traffic_impact"] == "yes" and entry.get("rejected"):
            # The verdict now passes, but the earlier build rejected the
            # event before it had an accepted row.  The row is rebuilt
            # from the pool entry, which is the source of the metadata.
            entry["accepted"] = accepted_row(entry, record, pool_rows)
            entry["rejected"] = None

    with JOURNAL.open("w", encoding="utf-8") as fh:
        for entry in entries:
            fh.write(json.dumps(entry, default=str) + "\n")

    print(f"\nre-decided {len(entries)} events, {changed} verdicts changed")
    print("now rerun scripts/build_canonical_dataset.py to rewrite the dataset")
    return 0


def accepted_row(entry: dict, record: dict, pool_rows: dict) -> dict:
    """Rebuild the accepted row from the record and the pool entry."""
    detail = record.get("traffic_detail") or {}
    control = record.get("control") or {}
    routing = record.get("routing") or {}
    row = pool_rows.get(entry["event_id"], {})
    return {
        "event_id": entry["event_id"],
        "name": row.get("name", ""),
        "date": row.get("date", ""),
        "start_utc": row.get("start_utc") or row.get("start_time_utc", ""),
        "end_utc": row.get("end_utc") or row.get("end_time_utc", ""),
        "victim_as": asn_int(row.get("victim_as", "")),
        "attacker_as": asn_int(row.get("attacker_as", "")),
        "leak_as": asn_int(row.get("leak_as", "")),
        "cause": (row.get("cause") or "").strip(),
        "subtype": (row.get("subtype") or "").strip(),
        "target_as": target_of(row),
        "routing_signal": routing.get("routing_signal", ""),
        "routing_note": routing.get("routing_note", ""),
        "routing_peak_A": routing.get("routing_peak_A", ""),
        "traffic_impact": "yes",
        "traffic_note": (record.get("traffic") or {}).get("traffic_note", ""),
        "traffic_z_min": round(float(detail.get("traffic_z_min", 0.0) or 0.0), 2),
        "traffic_pct_drop": round(
            float(detail.get("traffic_pct_drop", 0.0) or 0.0), 1
        ),
        "traffic_series": detail.get("traffic_series_id", ""),
        "traffic_scope": detail.get("traffic_scope", ""),
        "traffic_strategy": record.get("traffic_strategy", ""),
        "control_z_min": round(float(control.get("z_min", 0.0) or 0.0), 2),
        "control_pct_drop": round(float(control.get("pct_drop", 0.0) or 0.0), 1),
        "source": (row.get("source") or "").strip(),
        "source_url": (row.get("source_url") or "").strip(),
        "evidence_tier": (row.get("evidence_tier") or "A").strip(),
        "versions": ",".join(row.get("versions", []) if isinstance(
            row.get("versions", []), list) else [row.get("versions", "")]),
    }


def asn_int(value: str) -> str:
    text = (value or "").strip().upper()
    if text.startswith("AS"):
        text = text[2:]
    return text


def parse_ts(value: str):
    """Parse a UTC timestamp, the way the routing verifier does."""
    from detectors.gt_verify.routing_signal import parse_ts as _parse
    return _parse(value)


def target_of(row: dict) -> str:
    """The ASN the detector is run against."""
    cause = (row.get("cause") or "").strip()
    order = (("leak_as", "attacker_as", "victim_as")
             if cause in ("route_leak", "leak")
             else ("victim_as", "attacker_as", "leak_as"))
    for field in order:
        value = asn_int(row.get(field, ""))
        if value:
            return value
    return ""


if __name__ == "__main__":
    raise SystemExit(main())
