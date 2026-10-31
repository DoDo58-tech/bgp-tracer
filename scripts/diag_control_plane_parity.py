"""Compare the archive control plane with the detector's cached features.

Both are supposed to measure the same physical quantity -- the target's
own announcements per wall-clock slot -- over the same window.  If they
disagree, one of them is wrong, and the causal estimate inherits the
disagreement.  This prints both at the data plane's trough, so the
disagreement is visible rather than assumed away.
"""
from __future__ import annotations

import csv
import json
import sys
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

#: The channels the archive measures, paired with the detector's feature
#: that carries the same quantity.
PAIRS = (
    ("own_volume", "own_announcement_count"),
    ("own_withdrawal", "own_withdrawal_count"),
    ("involved_volume", "announcement_count"),
)


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
    """The archive evidence for this ASN, whichever window was scanned."""
    if not EVIDENCE.is_dir():
        return None
    for path in sorted(EVIDENCE.glob(f"{asn}_*.json")):
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
    return None


def detector_baseline(buckets: Dict[Any, Dict[str, Any]], feature: str,
                      window_start, window_end) -> Dict[str, float]:
    """The same-clock counterfactual from the detector's baseline buckets."""
    slot_keys = set()
    moment = window_start
    from datetime import timedelta
    while moment <= window_end:
        slot_keys.add(moment.strftime("%H:%M"))
        moment += timedelta(seconds=300)
    per_slot: Dict[str, List[float]] = {k: [] for k in slot_keys}
    for stamp, entry in buckets.items():
        if stamp < window_start:
            key = stamp.strftime("%H:%M")
            if key in per_slot:
                value = entry.get(feature)
                per_slot[key].append(float(value) if isinstance(value, (int, float)) else 0.0)
    return {k: float(np.mean(v)) if v else 0.0 for k, v in per_slot.items()}


def main() -> int:
    rows = list(csv.DictReader(open(GT, encoding="utf-8")))
    print(f"{'event':30s} {'trough':17s} {'dev':>8s} "
          f"{'archive own_vol':>16s} {'detector own_vol':>18s}")
    print("-" * 96)
    for row in rows:
        event_id = row["event_id"]
        asn = str(row.get("victim_as") or row.get("target_as"))
        match = resolve_cache(asn, row.get("start_utc"), row.get("end_utc"),
                              QUICK, event_id=event_id, allow_same_date=False)
        if match is None:
            print(f"{event_id[:28]:30s} NO CACHE")
            continue
        cache = json.loads(match.path.read_text(encoding="utf-8"))

        points = traffic_points(cache)
        if not points:
            print(f"{event_id[:28]:30s} NO TRAFFIC")
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
            print(f"{event_id[:28]:30s} NO TROUGH")
            continue
        trough_stamp, trough_dev = trough

        # ── the archive side ────────────────────────────────────────────
        evidence = archive_evidence(asn)
        archive_ratio = None
        if evidence and evidence.get("slots"):
            slots = evidence["slots"]
            index = {s: i for i, s in enumerate(slots)}
            centre = None
            for i, stamp in enumerate(slots):
                ts = parse_timestamp(stamp)
                if ts is None:
                    continue
                if abs((ts - trough_stamp).total_seconds()) <= 300:
                    centre = i
                    break
            if centre is not None:
                window = slots[max(0, centre - 3):centre + 4]
                values = (evidence.get("channels") or {}).get("own_volume") or []
                base = (evidence.get("baseline") or {}).get("own_volume") or {}
                obs = [values[index[s]] for s in window if s in index]
                exp = [base.get(s[11:16], 0.0) for s in window if s in index]
                exp = [e for e in exp if e > 0]
                if obs and exp:
                    archive_ratio = float(np.mean(obs)) / float(np.mean(exp))

        # ── the detector side ───────────────────────────────────────────
        oa = (cache.get("routing") or {}).get("outage_analysis") or {}
        event_b = read_buckets(oa.get("timeseries_event") or {})
        base_b = read_buckets(oa.get("timeseries_baseline") or {})
        detector_ratio = None
        if event_b:
            stamps = sorted(event_b)
            window_start, window_end = stamps[0], stamps[-1]
            baseline = detector_baseline(base_b, "own_announcement_count",
                                         window_start, window_end)
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
                    value = event_b[stamp].get("own_announcement_count")
                    obs.append(float(value) if isinstance(value, (int, float)) else 0.0)
                exp = [baseline.get(s.strftime("%H:%M"), 0.0) for s in stamps[lo:hi + 1]]
                exp = [e for e in exp if e > 0]
                if obs and exp:
                    detector_ratio = float(np.mean(obs)) / float(np.mean(exp))

        print(f"{event_id[:28]:30s} {str(trough_stamp)[:16]:17s} "
              f"{trough_dev:8.3f} "
              f"{('%.3f' % archive_ratio) if archive_ratio is not None else '-':>16s} "
              f"{('%.3f' % detector_ratio) if detector_ratio is not None else '-':>18s}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
