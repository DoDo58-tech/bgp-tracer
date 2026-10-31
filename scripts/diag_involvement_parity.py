"""Parity between the detector's cached series and the archive measurement.

The archive extractor and the detector's cached feature series are two
instruments that are supposed to measure the same physical quantity --
the target's announcements per wall-clock slot.  The archive adds the
target's *own* announcements, which the cached series did not have, so
the two cannot be compared on that channel directly.

They *can* be compared on the channel they share: the announcements
that involve the target.  If the two agree there, the instrument is
sound and the archive's own-channel measurement can be trusted; if they
disagree, one of them is wrong and the causal estimate inherits the
disagreement.
"""
from __future__ import annotations

import csv
import json
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.cache_resolution import resolve_cache  # noqa: E402
from agents.control_plane import read_buckets  # noqa: E402
from agents.paddle_attribution import traffic_deviation  # noqa: E402
from agents.temporal import parse_timestamp  # noqa: E402

GT = ROOT / "data_check/ground_truth_collection/final_ground_truth.csv"
QUICK = ROOT / "results/quick"
EVIDENCE = ROOT / "results/eval/control_evidence"


def traffic_impact(cache: Dict[str, Any]) -> Tuple[Optional[Any], Optional[Any]]:
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
    return None, None


def traffic_points(cache: Dict[str, Any]) -> List[Dict[str, Any]]:
    corr = cache.get("correlation") or {}
    tb = cache.get("traffic") or {}
    raw = None
    # The anomaly list is preferred: it is the record that carries the
    # measured value *and* the historical mean it was compared against.
    # The serialised event stream carries a placeholder baseline, so a
    # consumer that reads it first reconstructs a deviation of hundreds
    # of standard deviations with the sign inverted.
    for source in (tb.get("anomalies"), corr.get("traffic_events_full"),
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


def archive_evidence(asn: str) -> Optional[Dict[str, Any]]:
    if not EVIDENCE.is_dir():
        return None
    for path in sorted(EVIDENCE.glob(f"{asn}_*.json")):
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
    return None


def detector_same_clock(buckets: Dict[Any, Dict[str, Any]], feature: str,
                        stamps: List[Any]) -> Dict[str, float]:
    """The detector baseline's same-clock counterfactual."""
    positions = {s.strftime("%H:%M") for s in stamps}
    per_slot: Dict[str, List[float]] = {p: [] for p in positions}
    for stamp, entry in buckets.items():
        key = stamp.strftime("%H:%M")
        if key in per_slot:
            value = entry.get(feature)
            per_slot[key].append(
                float(value) if isinstance(value, (int, float)) else 0.0)
    return {k: float(np.mean(v)) if v else 0.0 for k, v in per_slot.items()}


def main() -> int:
    rows = list(csv.DictReader(open(GT, encoding="utf-8")))
    print("Involvement channel: the target's announcement rate as a multiple of")
    print("its own same-clock counterfactual, measured by two instruments.")
    print()
    print(f"{'event':30s} {'archive':>9s} {'detector':>9s} {'abs diff':>9s}")
    print("-" * 62)
    diffs: List[float] = []
    for row in rows:
        event_id = row["event_id"]
        asn = str(row.get("victim_as") or row.get("target_as"))
        match = resolve_cache(asn, row.get("start_utc"), row.get("end_utc"),
                              QUICK, event_id=event_id, allow_same_date=False)
        if match is None:
            continue
        cache = json.loads(match.path.read_text(encoding="utf-8"))
        points = traffic_points(cache)
        if not points:
            continue
        impact_start, impact_end = traffic_impact(cache)
        trough = None
        for point in points:
            if impact_start is not None and point["timestamp"] < impact_start:
                continue
            if impact_end is not None and point["timestamp"] > impact_end:
                continue
            if trough is None or point["deviation"] < trough[1]:
                trough = (point["timestamp"], point["deviation"])
        if trough is None:
            continue
        trough_stamp = trough[0]

        # ── archive ─────────────────────────────────────────────────────
        archive_ratio = None
        evidence = archive_evidence(asn)
        if evidence and evidence.get("slots"):
            slots = evidence["slots"]
            index = {s: i for i, s in enumerate(slots)}
            centre = None
            for i, stamp in enumerate(slots):
                ts = parse_timestamp(stamp)
                if ts is not None and abs((ts - trough_stamp).total_seconds()) <= 300:
                    centre = i
                    break
            if centre is not None:
                window = slots[max(0, centre - 3):centre + 4]
                values = (evidence.get("channels") or {}).get("involved_volume") or []
                base = (evidence.get("baseline") or {}).get("involved_volume") or {}
                obs = [values[index[s]] for s in window if s in index]
                exp = [base.get(s[11:16], 0.0) for s in window if s in index]
                exp = [e for e in exp if e > 0]
                if obs and exp:
                    archive_ratio = float(np.mean(obs)) / float(np.mean(exp))

        # ── detector ────────────────────────────────────────────────────
        oa = (cache.get("routing") or {}).get("outage_analysis") or {}
        event_b = read_buckets(oa.get("timeseries_event") or {})
        base_b = read_buckets(oa.get("timeseries_baseline") or {})
        detector_ratio = None
        if event_b and base_b:
            stamps = sorted(event_b)
            baseline = detector_same_clock(base_b, "announcement_count", stamps)
            centre = None
            for i, stamp in enumerate(stamps):
                if abs((stamp - trough_stamp).total_seconds()) <= 300:
                    centre = i
                    break
            if centre is not None:
                lo = max(0, centre - 3)
                hi = min(len(stamps) - 1, centre + 3)
                obs = []
                for stamp in stamps[lo:hi + 1]:
                    value = event_b[stamp].get("announcement_count")
                    obs.append(float(value) if isinstance(value, (int, float)) else 0.0)
                exp = [baseline.get(s.strftime("%H:%M"), 0.0) for s in stamps[lo:hi + 1]]
                exp = [e for e in exp if e > 0]
                if obs and exp:
                    detector_ratio = float(np.mean(obs)) / float(np.mean(exp))

        if archive_ratio is None and detector_ratio is None:
            continue
        diff = (abs(archive_ratio - detector_ratio)
                if archive_ratio is not None and detector_ratio is not None
                else None)
        if diff is not None:
            diffs.append(diff)
        print(f"{event_id[:28]:30s} "
              f"{('%.3f' % archive_ratio) if archive_ratio is not None else '-':>9s} "
              f"{('%.3f' % detector_ratio) if detector_ratio is not None else '-':>9s} "
              f"{('%.3f' % diff) if diff is not None else '-':>9s}")
    if diffs:
        print()
        print(f"n={len(diffs)}  mean |diff| = {float(np.mean(diffs)):.3f}  "
              f"median = {float(np.median(diffs)):.3f}  max = {float(np.max(diffs)):.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
