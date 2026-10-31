"""Evaluate PADDLE on the ground truth, measuring the control plane from
the archive.

The control plane is measured here rather than read from the detector's
cached features, because the cached features count the target's
*involvement* in routing updates while a causal measurement needs the
target's *own* announcements.  The archive scan is expensive, so its
result is cached on disk and reused.

The window the control plane is scanned over is the **union** of the
published event window and the traffic impact window, widened by a
margin.  That union matters: for several events the traffic fell
before the published window opened, and a control plane that was only
scanned over the published window would have no measurement at the
moment of the impact at all.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.cache_resolution import resolve_cache  # noqa: E402
from agents.control_plane_archive import (  # noqa: E402
    CONTROL_GRID_SECONDS,
    build_control_plane_evidence,
)
from agents.paddle_attribution import (  # noqa: E402
    PADDLE_PROTOCOL,
    R2T,
    T2R,
    UNKNOWN,
    traffic_deviation,
)
from agents.temporal import parse_timestamp  # noqa: E402

GT_CSV = ROOT / "data_check/ground_truth_collection/final_ground_truth.csv"
QUICK = ROOT / "results/quick"
EVIDENCE_CACHE = ROOT / "results" / "eval" / "control_evidence"

#: The margin around the union of the two windows that the control
#: plane is scanned over.
SCAN_MARGIN = timedelta(hours=2)


def cache_key(asn: str, lo: datetime, hi: datetime) -> Path:
    tag = f"{asn}_{lo:%Y%m%d%H%M}_{hi:%Y%m%d%H%M}"
    return EVIDENCE_CACHE / f"{tag}.json"


def load_or_scan(asn: str, lo: datetime, hi: datetime,
                 *, refresh: bool = False) -> Dict[str, Any]:
    """The control-plane evidence for one window, cached on disk."""
    path = cache_key(asn, lo, hi)
    if path.is_file() and not refresh:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    evidence = build_control_plane_evidence(asn, lo, hi)
    payload = {
        "slots": [s.isoformat() for s in evidence.slots],
        "channels": evidence.channels,
        "baseline": evidence.baseline,
        "rows_scanned": evidence.rows_scanned,
        "files_scanned": evidence.files_scanned,
        "error": evidence.error,
    }
    EVIDENCE_CACHE.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return payload


def traffic_impact(cache: Dict[str, Any]) -> Tuple[Optional[datetime],
                                                  Optional[datetime]]:
    """The traffic detector's own impact window."""
    tb = cache.get("traffic") or {}
    for key in ("consecutive_anomaly_windows", "expanded_windows"):
        windows = tb.get(key)
        if isinstance(windows, list) and windows:
            first = windows[0]
            if not isinstance(first, dict):
                continue
            start = parse_timestamp(first.get("start"))
            end = parse_timestamp(first.get("end"))
            if start is not None:
                return (start, end if end is not None else start)
    period = tb.get("original_outage_period")
    if isinstance(period, dict):
        start = parse_timestamp(period.get("start_time"))
        end = parse_timestamp(period.get("end_time"))
        if start is not None:
            return (start, end if end is not None else start)
    return None, None


def traffic_points(cache: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Every traffic observation with its signed deviation."""
    corr = cache.get("correlation") or {}
    tb = cache.get("traffic") or {}
    raw = None
    for source in (corr.get("traffic_events_full"), tb.get("anomalies"),
                   corr.get("traffic_events")):
        if isinstance(source, list) and source:
            raw = source
            break
    if raw is None:
        return []
    out: List[Dict[str, Any]] = []
    for event in raw:
        if not isinstance(event, dict):
            continue
        stamp = parse_timestamp(event.get("timestamp") or event.get("time"))
        if stamp is None:
            continue
        deviation = traffic_deviation({"raw_event": event})
        if deviation is None:
            continue
        out.append({"timestamp": stamp, "deviation": deviation})
    return out


def slot_ratio(evidence: Dict[str, Any], channel: str,
               stamps: List[str]) -> Optional[float]:
    """The observed rate over the slots, as a multiple of the same-clock
    baseline."""
    slots = evidence.get("slots") or []
    if not slots:
        return None
    values = (evidence.get("channels") or {}).get(channel) or []
    if len(values) != len(slots):
        return None
    index = {s: i for i, s in enumerate(slots)}
    observed_list: List[float] = []
    expected_list: List[float] = []
    baseline = (evidence.get("baseline") or {}).get(channel) or {}
    for stamp in stamps:
        i = index.get(stamp)
        if i is None:
            continue
        observed_list.append(float(values[i]))
        expected_list.append(float(baseline.get(stamp[11:16], 0.0)))
    if not observed_list:
        return None
    expected = float(np.mean(expected_list))
    observed = float(np.mean(observed_list))
    if expected <= 0:
        return None
    return observed / expected


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--gt", default=str(GT_CSV))
    ap.add_argument("--out", default=str(ROOT / "results" / "eval" / "paddle_eval.csv"))
    ap.add_argument("--only", default="")
    ap.add_argument("--refresh", action="store_true")
    ap.add_argument("--half-width", type=int, default=3,
                    help="slots on each side of the trough")
    args = ap.parse_args()

    rows = list(csv.DictReader(open(args.gt, encoding="utf-8")))
    records: List[Dict[str, Any]] = []

    for row in rows:
        event_id = row["event_id"]
        if args.only and event_id != args.only:
            continue
        asn = row.get("victim_as") or row.get("target_as")
        match = resolve_cache(asn, row.get("start_utc"), row.get("end_utc"),
                              QUICK, event_id=event_id, allow_same_date=False)
        if match is None:
            records.append({"event_id": event_id, "outcome": "no_cache"})
            continue
        cache = json.loads(match.path.read_text(encoding="utf-8"))

        gt_start = parse_timestamp(row.get("start_utc"))
        gt_end = parse_timestamp(row.get("end_utc"))
        impact_start, impact_end = traffic_impact(cache)
        points = traffic_points(cache)

        # The data plane's trough: the sharpest downward deviation
        # inside the impact window.
        trough: Optional[Tuple[datetime, float]] = None
        for point in points:
            if impact_start is not None and point["timestamp"] < impact_start:
                continue
            if impact_end is not None and point["timestamp"] > impact_end:
                continue
            if trough is None or point["deviation"] < trough[1]:
                trough = (point["timestamp"], point["deviation"])

        if trough is None:
            # Fall back to the whole record, so the reason is visible.
            for point in points:
                if trough is None or point["deviation"] < trough[1]:
                    trough = (point["timestamp"], point["deviation"])
        if trough is None:
            records.append({"event_id": event_id, "outcome": "no_trough"})
            continue
        trough_stamp, trough_deviation = trough

        # The control plane is scanned over the union of the published
        # window and the impact window.
        lo_candidates = [t for t in (gt_start, impact_start) if t is not None]
        hi_candidates = [t for t in (gt_end, impact_end) if t is not None]
        lo = min(lo_candidates) - SCAN_MARGIN
        hi = max(hi_candidates) + SCAN_MARGIN

        evidence = load_or_scan(str(asn), lo, hi, refresh=args.refresh)
        if not evidence.get("slots"):
            records.append({"event_id": event_id, "outcome": "no_control_plane"})
            continue

        # The slots around the trough.
        index = {s: i for i, s in enumerate(evidence["slots"])}
        centre = None
        for i, stamp in enumerate(evidence["slots"]):
            if abs((parse_timestamp(stamp) - trough_stamp).total_seconds()) \
                    <= CONTROL_GRID_SECONDS:
                centre = i
                break
        if centre is None:
            records.append({"event_id": event_id, "outcome": "trough_outside_scan"})
            continue
        window = evidence["slots"][
            max(0, centre - args.half_width):
            centre + args.half_width + 1]

        best: Optional[Tuple[float, str, float]] = None
        per_channel: Dict[str, Any] = {}
        for channel in ("own_volume", "own_withdrawal", "involved_volume",
                        "origin_change", "path_change"):
            ratio = slot_ratio(evidence, channel, window)
            if ratio is None:
                per_channel[channel] = None
                continue
            deviation = abs(ratio - 1.0)
            per_channel[channel] = round(ratio, 4)
            if best is None or deviation > best[0]:
                best = (deviation, channel, ratio)

        records.append({
            "event_id": event_id,
            "cause": row.get("cause", ""),
            "outcome": "measured",
            "trough": trough_stamp.isoformat(),
            "trough_deviation": round(trough_deviation, 4),
            "channel": best[1] if best else "",
            "ratio": round(best[2], 4) if best else None,
            "deviation": round(best[0], 4) if best else None,
            "sign_ok": (best is not None and (
                (best[2] < 1.0) == (trough_deviation < 0))),
            "per_channel": json.dumps(per_channel),
            "rows_scanned": evidence.get("rows_scanned"),
        })

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    if records:
        keys: List[str] = []
        for record in records:
            for key in record:
                if key not in keys:
                    keys.append(key)
        with open(out, "w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=keys)
            writer.writeheader()
            writer.writerows(records)

    print(f"{'event':34s} {'outcome':10s} {'channel':18s} {'ratio':>8s} "
          f"{'dev':>8s} {'trough_dev':>10s} sign")
    for record in records:
        print(f"{record['event_id'][:32]:34s} {record.get('outcome',''):10s} "
              f"{str(record.get('channel','')):18s} "
              f"{str(record.get('ratio','')):>8s} "
              f"{str(record.get('deviation','')):>8s} "
              f"{str(record.get('trough_deviation','')):>10s} "
              f"{record.get('sign_ok','')}")
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
