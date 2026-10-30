"""Traffic-impact measurement for one ground-truth event.

The question this answers is: *does the affected network measurably lose
traffic while the routing anomaly is happening?*  Without that, an event
is a routing curiosity, not a business incident.

Three things make the measurement meaningful.

**The right series.**  An outage or a leak is measured on the network
that *serves* the affected traffic -- the victim of the event.  A hijack
is a prefix-level event, so it is measured on the hijacked prefix: the
rest of the victim's traffic carries on, so the ASN-level series would
show nothing.

**One scale for the whole comparison.**  Radar's ``MIN0_MAX``
normalisation is applied *per request*: the same absolute traffic level
is reported as 1.0 in every window that contains it.  Two separate
requests therefore cannot be compared -- the maximum of the event window
and the maximum of the baseline week are each 1.0 by construction, and
any difference between them is an artefact of the normalisation, not of
the traffic.  The event window and all the baseline weeks are therefore
fetched as *one* span, so a single normalisation covers all of them and
the comparison is meaningful.

**A control.**  A drop that also happens on an unaffected network is
weather, not an incident.  Every event is measured on a control network
over the same window; the drop only counts as an impact when the control
stayed flat.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from utils.logger import logger  # noqa: E402

#: How many weeks of baseline are compared.
BASELINE_WEEKS = 4

#: The measurement window is padded on both sides.  Radar's 15-minute
#: series is sparse for short windows -- a 45-minute event yields four
#: samples, which cannot carry a z-score -- and the data itself lags by
#: a couple of hours.  The padding mirrors the traffic detector's own
#: query window (start - 1 day, end + 6 hours), so the ground truth and
#: the detector look at the same data.
MEASURE_LEAD = timedelta(days=1)
MEASURE_TAIL = timedelta(hours=6)

#: The samples that are taken to be "the event".  A 45-minute incident
#: only holds three or four 15-minute samples, so the event is read with
#: a couple of hours of slack on either side.  The slack absorbs the
#: uncertainty in the published incident time and Radar's own lag.
EVENT_LEAD = timedelta(hours=2)
EVENT_TAIL = timedelta(hours=2)

#: The z-score below which the drop is not considered an impact.
Z_IMPACT_THRESHOLD = -2.5

#: The relative drop below which the impact is not considered.
PCT_IMPACT_THRESHOLD = 10.0

#: The minimum number of samples the measurement window must hold for
#: the measurement to mean anything.
MIN_WINDOW_SAMPLES = 12

#: The minimum number of samples the event itself must hold.
MIN_EVENT_SAMPLES = 8

#: The networks used as the control.  They are large and well
#: connected, and no event in the dataset involves them, so their
#: traffic is a proxy for "what the internet looked like during the
#: event".
#:
#: Only the *first* usable one is used as the control.  The control's
#: job is to answer "did the internet as a whole have a bad day", and
#: one large network answers that as well as eight do -- at a ninth of
#: the API calls, which matters because the control is fetched for
#: every event.
CONTROL_ASNS = (16509, 15169, 13335, 7018, 3356, 1299, 174, 6939)

#: Where the fetched series are cached.  Radar is slow and rate-limited,
#: and the control series are the same for every event in a window.
CACHE_DIR = ROOT / "data" / "traffic_cache"


@dataclass
class TrafficMeasurement:
    """What the traffic series shows for one event."""

    event_id: str = ""
    #: The series that was measured ("asn" or "prefix").
    scope: str = ""
    #: The ASN or prefix that was measured.
    series_id: str = ""
    #: The number of samples in the measurement window.
    n_window: int = 0
    #: The number of samples in the event window itself.
    n_event: int = 0
    #: The number of samples in the baseline.
    n_baseline: int = 0
    #: The lowest z-score of the measurement window against the baseline.
    z_min: float = 0.0
    #: The relative drop at the trough, in percent.
    pct_drop: float = 0.0
    #: The same measures for the control series.
    control_z_min: float = 0.0
    control_pct_drop: float = 0.0
    #: The samples of the measurement window.
    window: List[Tuple[str, float]] = field(default_factory=list)
    #: The timestamp of the trough of the measurement window.
    trough_time: str = ""
    #: Whether the trough sits close enough to the event to be attributed
    #: to it.
    trough_in_event: bool = False
    #: Set when the series could not be measured.
    error: str = ""
    #: Why the measurement failed, in words.
    no_data_reason: str = ""

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "traffic_scope": self.scope,
            "traffic_series_id": self.series_id,
            "traffic_n_window": self.n_window,
            "traffic_n_event": self.n_event,
            "traffic_n_baseline": self.n_baseline,
            "traffic_z_min": round(self.z_min, 3),
            "traffic_pct_drop": round(self.pct_drop, 2),
            "traffic_control_z_min": round(self.control_z_min, 3),
            "traffic_control_pct_drop": round(self.control_pct_drop, 2),
            "traffic_trough_time": self.trough_time,
            "traffic_trough_in_event": self.trough_in_event,
            "traffic_error": self.error,
            "traffic_no_data_reason": self.no_data_reason,
        }


def _z_and_drop(window: np.ndarray, baseline: np.ndarray) -> Tuple[float, float]:
    """The worst z-score of the window and the drop at its trough.

    The window and the baseline are right-aligned, so index *i* of one
    corresponds to the same clock position in the other -- that is what
    makes a per-sample z-score meaningful.
    """
    if window.size == 0 or baseline.size == 0:
        return 0.0, 0.0
    n = min(window.size, baseline.size)
    w = window[-n:]
    b = baseline[-n:]

    b_mean = float(np.mean(b))
    b_std = float(np.std(b))
    if b_std <= 0:
        # A flat baseline has no spread, so a z-score would divide by
        # zero.  The relative drop is still meaningful, so the z-score is
        # reported as 0 and the drop carries the verdict.
        z_min = 0.0
    else:
        z_min = float(np.min((w - b_mean) / b_std))

    trough = float(np.min(w))
    pct_drop = ((b_mean - trough) / b_mean * 100.0) if b_mean > 0 else 0.0
    return z_min, pct_drop


def _align_baseline(weeks: Sequence[np.ndarray], length: int) -> np.ndarray:
    """Right-align the baseline weeks and average them."""
    usable = [w for w in weeks if w.size > 0]
    if not usable:
        return np.array([])
    tail = [w[-length:] if w.size >= length else w for w in usable]
    return np.mean(np.vstack(tail), axis=0)


def _within(stamp: str, start: datetime, end: datetime) -> bool:
    """Whether a timestamp sits inside a window.

    The timestamp comes from Radar as an ISO string in UTC.  The
    window's bounds are naive datetimes in UTC, so the stamp is
    converted to UTC and its offset is dropped before the comparison.
    """
    if not stamp:
        return False
    try:
        moment = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        return False
    if moment.tzinfo is not None:
        moment = moment.astimezone(timezone.utc).replace(tzinfo=None)
    return start <= moment <= end


def _trough_time(stamps: Sequence[str], series: np.ndarray) -> str:
    """The timestamp of the lowest sample of the series."""
    if series.size == 0 or not stamps:
        return ""
    index = int(np.argmin(series))
    if index >= len(stamps):
        return ""
    return stamps[index]


def _spans(start: datetime, end: datetime) -> List[Tuple[datetime, datetime]]:
    """The measurement window and the baseline weeks, as one span list.

    All of these are fetched together, so Radar normalises them on one
    scale and they can be compared with each other.
    """
    window_start = start - MEASURE_LEAD
    window_end = end + MEASURE_TAIL
    spans = [(window_start, window_end)]
    for week in range(1, BASELINE_WEEKS + 1):
        shift = timedelta(days=7 * week)
        spans.append((window_start - shift, window_end - shift))
    return spans


def _cache_key(series_id: str, scope: str, lo: datetime, hi: datetime) -> Path:
    tag = "prefix" if scope == "prefix" else "asn"
    name = f"{tag}_{series_id.replace('/', '_')}_{lo:%Y%m%d%H%M}_{hi:%Y%m%d%H%M}.json"
    return CACHE_DIR / name


def _cache_path(series_id: str, scope: str, lo: datetime, hi: datetime,
                endpoint: str = "http") -> Path:
    tag = "prefix" if scope == "prefix" else "asn"
    safe = series_id.replace("/", "_").replace(":", "_")
    return CACHE_DIR / f"{endpoint}_{tag}_{safe}_{lo:%Y%m%d%H%M}_{hi:%Y%m%d%H%M}.json"


def _read_cache(path: Path) -> Optional[Tuple[List[str], List[float]]]:
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    stamps = payload.get("timestamps") or []
    values = payload.get("values") or []
    if not stamps:
        return None
    return list(stamps), [float(v) for v in values]


def _write_cache(path: Path, stamps: Sequence[str], values: Sequence[float]) -> None:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps({"timestamps": list(stamps), "values": list(values)}),
            encoding="utf-8",
        )
        tmp.replace(path)
    except OSError as exc:
        logger.debug("[gt-verify] traffic cache write failed: %r", exc)


def _fetch_shared(api, series_id: str, scope: str,
                  spans: Sequence[Tuple[datetime, datetime]],
                  endpoint: str = "http",
                  ) -> Tuple[Dict[Tuple[datetime, datetime], Tuple[List[str], List[float]]], str]:
    """Fetch every span on one scale.

    The project's ``RadarSpanFetcher`` already solves the shared-scale
    problem: it fetches the whole span in chunks and fits a single
    normalisation onto all of them.  Reusing it keeps the ground truth
    on exactly the data the detector sees.

    All the spans are fetched in *one* call.  Fetching them one by one
    would give each span its own normalisation, which is precisely the
    artefact this module exists to avoid.
    """
    from detectors.traffic.traffic_detector import RadarSpanFetcher

    if scope == "global":
        fetcher = RadarSpanFetcher(api, 0, endpoint=endpoint,
                                   global_series=True)
    else:
        fetcher = RadarSpanFetcher(api, int(series_id), endpoint=endpoint)

    lo = min(s for s, _ in spans)
    hi = max(e for _, e in spans)
    cache_path = _cache_path(str(series_id), scope, lo, hi, endpoint)
    cached = _read_cache(cache_path)
    if cached is not None:
        stamps, values = cached
    else:
        last_error = ""
        try:
            stamps, values = fetcher.fetch(list(spans))
        except Exception as exc:  # noqa: BLE001 - the failure is the result
            last_error = str(exc)[:300]
            stamps, values = [], []
        if stamps:
            _write_cache(cache_path, stamps, values)
        else:
            return {
                span: ([], []) for span in spans
            }, last_error or "no samples"

    out: Dict[Tuple[datetime, datetime], Tuple[List[str], List[float]]] = {}
    for span in spans:
        lo_s = span[0].strftime("%Y-%m-%dT%H:%M:%SZ")
        hi_s = span[1].strftime("%Y-%m-%dT%H:%M:%SZ")
        picked = [
            (t, v) for t, v in zip(stamps, values) if lo_s <= t <= hi_s
        ]
        out[span] = ([t for t, _ in picked], [v for _, v in picked])

    if not any(v[0] for v in out.values()):
        return out, "no samples"
    return out, ""


def _slice(series: Tuple[List[str], List[float]], start: datetime,
           end: datetime) -> np.ndarray:
    """The samples of the series that fall inside the window."""
    stamps, values = series
    if not stamps:
        return np.array([])
    lo = start.strftime("%Y-%m-%dT%H:%M:%SZ")
    hi = end.strftime("%Y-%m-%dT%H:%M:%SZ")
    picked = [v for t, v in zip(stamps, values) if lo <= t <= hi]
    return np.asarray(picked, dtype=float)


def measure(api, series_id: str, start: datetime, end: datetime,
            event_id: str = "", scope: str = "asn",
            use_cache: bool = True,
            endpoint: str = "http") -> TrafficMeasurement:
    """Measure the traffic impact on one series over one event window."""
    measurement = TrafficMeasurement(
        event_id=event_id, scope=scope, series_id=str(series_id),
    )

    spans = _spans(start, end)
    fetched, error = _fetch_shared(api, str(series_id), scope, spans,
                                   endpoint=endpoint)
    if error:
        measurement.error = error
        text = error.lower()
        if "must be equal to or later than" in text or "retention" in text:
            measurement.no_data_reason = "before_radar_retention"
        elif "auth" in text:
            measurement.no_data_reason = "cloudflare_authentication_failed"
        else:
            measurement.no_data_reason = "cloudflare_no_series"
        return measurement

    window_span = spans[0]
    stamps, values = fetched[window_span]
    if not stamps:
        measurement.error = "no samples in measurement window"
        measurement.no_data_reason = "cloudflare_no_series"
        return measurement

    series = np.asarray(values, dtype=float)
    measurement.window = [(stamps[i], float(series[i])) for i in range(series.size)]
    measurement.n_window = int(series.size)
    if measurement.n_window < MIN_WINDOW_SAMPLES:
        measurement.error = "too few samples in measurement window"
        measurement.no_data_reason = "cloudflare_no_points"
        return measurement

    # A series that is identically zero is not a measurement -- it is the
    # absence of one.  Radar keeps the DNS resolver series only from
    # 2025 onwards, and for an earlier period it answers with zeros
    # rather than with an error.  Treating that as "the traffic did not
    # move" would be a false negative, so it is reported as an
    # unavailable series and the caller falls back to another one.
    if not np.any(series > 0):
        measurement.error = "series is identically zero"
        measurement.no_data_reason = "radar_series_not_retained"
        return measurement

    # The event itself: the samples around the incident.  The drop is
    # measured here rather than over the whole padded window, because a
    # dip that happens to sit elsewhere in the padded window says nothing
    # about this event.
    event_lo = (start - EVENT_LEAD).strftime("%Y-%m-%dT%H:%M:%SZ")
    event_hi = (end + EVENT_TAIL).strftime("%Y-%m-%dT%H:%M:%SZ")
    event_idx = [i for i, t in enumerate(stamps) if event_lo <= t <= event_hi]
    if len(event_idx) < MIN_EVENT_SAMPLES:
        measurement.error = "too few samples around the event"
        measurement.no_data_reason = "cloudflare_no_points"
        return measurement
    event = series[event_idx[0]: event_idx[-1] + 1]
    measurement.n_event = int(event.size)

    # The baseline weeks, each on the same scale as the event window.
    weeks: List[np.ndarray] = []
    for week in range(1, BASELINE_WEEKS + 1):
        span = spans[week]
        base = _slice(fetched[span], span[0], span[1])
        if base.size:
            weeks.append(base)
    if not weeks:
        measurement.error = "no baseline"
        measurement.no_data_reason = "no_baseline"
        return measurement

    length = int(min(event.size, min(w.size for w in weeks)))
    if length < MIN_EVENT_SAMPLES:
        measurement.error = "baseline too short"
        measurement.no_data_reason = "baseline_too_short"
        return measurement
    baseline = _align_baseline(weeks, length)
    measurement.n_baseline = int(baseline.size)

    measurement.z_min, measurement.pct_drop = _z_and_drop(event, baseline)
    measurement.trough_time = _trough_time(
        [stamps[i] for i in event_idx], event
    )
    # The trough has to sit inside the *padded* window -- the published
    # incident window plus the same slack the measurement itself uses.
    #
    # The slack is not slack for its own sake: Radar's series timestamps
    # do not line up exactly with the incident times in the public
    # reports, and a 15-minute sample that straddles the start of an
    # incident is routinely stamped on the far side of it.  Several of
    # the strongest events in the dataset have their trough an hour or
    # two before the published start, so a tighter rule would discard
    # the events with the clearest evidence.
    #
    # The check is still worth making explicit: the trough has to be in
    # the window that was actually compared against the baseline, or the
    # drop and the window would be two different things.
    measurement.trough_in_event = _within(
        measurement.trough_time,
        start - EVENT_LEAD,
        end + EVENT_TAIL,
    )
    return measurement


def measure_control(api, start: datetime, end: datetime,
                    exclude: Sequence[str] = (),
                    endpoint: str = "http") -> Tuple[float, float]:
    """Measure a control network over the same window.

    The control is a large, well-connected network that the event does
    not touch.  If the control's traffic also drops, then the drop that
    was measured on the victim is not specific to the incident.

    The networks in ``exclude`` are skipped: a control that *is* the
    victim would show the same drop and would make every incident look
    unspecific.
    """
    skip = {str(a).replace("AS", "") for a in exclude if a}
    for asn in CONTROL_ASNS:
        if str(asn) in skip:
            continue
        measurement = measure(api, str(asn), start, end, scope="asn",
                              endpoint=endpoint)
        if measurement.error:
            continue
        # One usable control is enough: it answers "did the internet as
        # a whole have a bad day", and fetching eight of them for every
        # event costs eight times the API calls for no extra
        # information.
        return measurement.z_min, measurement.pct_drop
    return 0.0, 0.0


def verdict(measurement: TrafficMeasurement, control_z: float,
            control_drop: float) -> dict:
    """Turn the measurements into the verdict the dataset stores.

    The impact has to be visible *and* specific: the z-score must be
    below the threshold and the control must not show the same drop.
    """
    if measurement.error:
        return {
            "traffic_impact": "unknown",
            "traffic_note": measurement.error,
        }

    # The impact has to be visible, near the event, and specific.
    visible = (
        measurement.z_min <= Z_IMPACT_THRESHOLD
        or measurement.pct_drop >= PCT_IMPACT_THRESHOLD
    )
    near = measurement.trough_in_event

    # A control that dropped by the same amount means the drop is not
    # attributable to the event.
    #
    # Both tests have to hold for the impact to be *specific*.  The
    # earlier version accepted either one, which let an event through
    # when the control network had fallen further than the victim: a
    # victim z of -4 against a control z of +6.7 is a network that was
    # doing *better* than the internet around it, and the drop is not
    # the event's doing.
    specific = (
        measurement.pct_drop - control_drop >= PCT_IMPACT_THRESHOLD
        and measurement.z_min <= control_z - 1.0
    )

    if visible and near and specific:
        verdict_value = "yes"
    elif visible and near:
        verdict_value = "ambiguous"
    elif visible:
        verdict_value = "ambiguous_far_from_event"
    else:
        verdict_value = "no"

    # A drop that is only visible because the padded window reaches
    # outside the incident is a different situation from a drop that
    # is visible but not specific.  The two are told apart so a reader
    # can see which one rejected an event.
    if visible and not near:
        reason = f"drop_is_outside_the_incident_window({measurement.trough_time})"
    elif not specific:
        reason = "the_control_network_showed_the_same_drop"
    else:
        reason = ""

    note = (
        f"z_min={measurement.z_min:.2f} drop={measurement.pct_drop:.1f}% "
        f"trough={measurement.trough_time or 'n/a'} "
        f"(control z={control_z:.2f} drop={control_drop:.1f}%)"
    )
    if reason:
        note += f"; {reason}"
    return {
        "traffic_impact": verdict_value,
        "traffic_note": note,
    }
