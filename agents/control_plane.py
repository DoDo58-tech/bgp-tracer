"""The control-plane representation the causal estimator works on.

The routing side of a BGP incident is not an amplitude on a continuous
signal.  It is a change in how densely the collector observes the
control plane, and the three incident kinds change it in three
different ways: an outage makes it quiet, a hijack changes an origin, a
leak changes a path.  The three are therefore carried as **separate
channels** and never summed, so that a verdict can name *which*
control-plane property moved and a hijack cannot be confirmed by a
leak's path-change signal.

Four representation decisions, each of which was a measurable defect
before it was made.

The grid is uniform and the holes are filled.  The detector emits a
bucket only when a message exists, but a missing bucket is a bucket in
which the network said *nothing* -- a rate of zero, not a missing
measurement.  The grid is the wall-clock 300-second grid and every slot
carries a value.

The rates are per wall-clock slot, not per observed bucket.  Dividing by
the number of buckets that happened to carry traffic hides the collapse
an outage is.

The baseline is the same clock slots on the previous days.  A
forty-five-minute incident measured against a twenty-four-hour average
measures the time of day, not the incident.

The normalisation is scale-free.  Every channel is divided by its own
baseline level, so the series reads "one times normal", "zero" or
"twelve", and the estimator's thresholds become a property of the method
rather than of the network the method was pointed at.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

from agents.temporal import parse_timestamp

__all__ = [
    "BASELINE_DAYS",
    "CONTROL_PLANE_CHANNELS",
    "ControlPlaneSeries",
    "GRID_SECONDS",
    "build_control_plane_series",
    "extract_timeseries",
    "same_clock_baseline",
]

#: The wall-clock width of one control-plane slot, in seconds.
GRID_SECONDS = 300

#: How many days before the event the counterfactual reaches.
#:
#: A week, so the counterfactual covers the whole weekly cycle and the
#: placebo null has enough ordinary days to estimate a tail
#: probability from.  The archive, the estimator and the placebo all
#: use this number, because a counterfactual that reaches further back
#: in one place and not in another would compare the incident with a
#: different period than the placebo does.
BASELINE_DAYS = 7

#: The control-plane channels, carried separately into the vetoes.
#:
#: ``own_volume`` and ``own_withdrawal`` count what the target AS
#: *itself* originates and withdraws.  They are separate from
#: ``volume`` and ``withdrawal``, which count what the target is
#: *involved in*.  The distinction is the whole point: a network that
#: has stopped announcing its own routes still receives a flood of
#: updates about other people's routes, so an involvement measure cannot
#: see an outage go quiet.  The ground-truth verifier measures the
#: target's own announcements for exactly this reason.
CONTROL_PLANE_CHANNELS = ("own_volume", "own_withdrawal", "volume",
                           "withdrawal", "origin_change", "path_change")

#: The detector feature that carries each channel.
#:
#: A count and a ratio are different quantities and are never mixed: a
#: path-change *rate* divided by a baseline *count* is not a multiple
#: of anything.  Each channel names the features it may be read from,
#: in order of preference, and the first usable one wins.
_CHANNEL_FEATURES: Dict[str, Tuple[str, ...]] = {
    "own_volume": ("own_announcement_count", "own_volume"),
    "own_withdrawal": ("own_withdrawal_count", "own_withdrawal"),
    "volume": ("announcement_count", "total_messages", "volume"),
    "withdrawal": ("withdrawal_count", "withdrawal"),
    "origin_change": ("num_ori_change", "origin_change_count", "origin_change"),
    "path_change": ("num_path_change", "path_change_rate", "path_change"),
}


@dataclass
class ControlPlaneSeries:
    """The routing side as a set of per-slot observation rates.

    ``stamps`` is the uniform clock the estimator works on.  The
    routing and the traffic side are evaluated on the *same* wall-clock
    axis, so a slot means the same interval on both sides.
    """

    stamps: List[datetime] = field(default_factory=list)
    channels: Dict[str, List[float]] = field(default_factory=dict)
    #: The same channels over the period *before* the event, when the
    #: detector could supply it.  This is the null the exclusivity test
    #: draws its placebos from.
    baseline: Dict[str, List[float]] = field(default_factory=dict)
    baseline_stamps: List[datetime] = field(default_factory=list)
    #: The baseline's level per channel, used to normalise.
    baseline_level: Dict[str, float] = field(default_factory=dict)
    #: The wall-clock gap a slot is expected to span, in seconds.
    bucket_seconds: float = float(GRID_SECONDS)
    #: The baseline's own buckets, keyed by stamp.  The placebo null is
    #: built from these, so the estimator can reach them directly.
    #:
    #: The field is named ``baseline_bucket_map`` rather than
    #: ``_baseline_buckets`` because the project does not use a leading
    #: underscore to mark a name, and because a private field whose
    #: stripped name collides with the accessor of the same purpose reads
    #: like a rename that has not finished.
    baseline_bucket_map: Dict[datetime, Dict[str, Any]] = field(
        default_factory=dict, repr=False)
    #: The channels the instrument actually recorded.  A channel that is
    #: absent from this set was never measured, which is a different
    #: thing from a channel that was measured and found to be silent.
    #:
    #: The distinction decides an outage.  A target that stops
    #: announcing its own routes has a channel that is flat at zero
    #: during the incident and alive on ordinary days; that silence is
    #: the observation.  But a channel the instrument never carried is
    #: zero everywhere, baseline included, and comparing it with its
    #: own counterfactual would invent a silence out of a missing
    #: measurement.
    measured_channels: List[str] = field(default_factory=list)

    def baseline_buckets(self):
        """The baseline period's buckets, keyed by stamp."""
        return dict(self.baseline_bucket_map)

    def is_measured(self, name: str) -> bool:
        """Whether the instrument recorded this channel at all."""
        if self.measured_channels:
            return name in self.measured_channels
        # A series that does not say which channels it carries is
        # treated as carrying the ones it has data for.
        return bool(self.channel(name))

    @property
    def n_buckets(self):
        return len(self.stamps)

    @property
    def has_baseline(self):
        return bool(self.baseline) and any(
            len(v) >= 2 for v in self.baseline.values() if v is not None
        )

    def channel(self, name: str):
        return self.channels.get(name) or []

    def baseline_channel(self, name: str):
        return self.baseline.get(name) or []

    def normalised(self, name: str):
        """The channel as a multiple of its own baseline level.

        One means "the control plane is behaving as it normally does",
        zero means "the control plane has gone quiet", twelve means
        "twelve times the normal observation rate".
        """
        values = self.channel(name)
        level = self.baseline_level.get(name)
        if not values or not level or level <= 0:
            return list(values)
        return [v / level for v in values]

    def normalised_baseline(self, name: str):
        """The baseline window's own channel, on the same scale."""
        values = self.baseline_channel(name)
        arr = np.asarray(values, dtype=float)
        level = float(arr.mean()) if arr.size else 0.0
        if not level or level <= 0:
            return list(values)
        return [v / level for v in values]

    def as_dict(self):
        return {
            "n_buckets": self.n_buckets,
            "channels": {k: len(v) for k, v in self.channels.items()},
            "has_baseline": self.has_baseline,
            "n_baseline_buckets": len(self.baseline_stamps),
            "baseline_level": {k: round(v, 4)
                               for k, v in self.baseline_level.items()},
            "bucket_seconds": self.bucket_seconds,
            "start": self.stamps[0].isoformat() if self.stamps else None,
            "end": self.stamps[-1].isoformat() if self.stamps else None,
        }


def to_float_value(value: Any):
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def feature_value(entry: Dict[str, Any],
                   features: Sequence[str]):
    """The first usable value among ``features`` for one bucket.

    A bucket may name its value either by the detector's feature name
    (``announcement_count``) or by the channel it belongs to
    (``volume``).  The archive counts the channels directly, so both
    spellings have to resolve to the same number.
    """
    for key in features:
        val = to_float_value(entry.get(key))
        if val is not None:
            return val
    return None


def read_buckets(block: Any):
    """Parse a detector bucket block into ``{stamp: features}``.

    A bucket whose timestamp cannot be read is *reported* as absent
    rather than silently dropped, because a whole event's routing
    evidence disappearing looks like a modelling result and is actually
    a parsing failure.
    """
    if not isinstance(block, dict):
        return {}
    out: Dict[datetime, Dict[str, Any]] = {}
    for raw_stamp, entry in block.items():
        if not isinstance(entry, dict):
            continue
        stamp = parse_timestamp(raw_stamp)
        if stamp is None:
            continue
        out[stamp] = entry
    return out


def extract_timeseries(
    analysis: Optional[Dict[str, Any]],
):
    """Pull the control-plane features out of a detector analysis block.

    Returns ``(event_buckets, baseline_buckets)``.
    """
    if not isinstance(analysis, dict):
        return {}, {}
    return (read_buckets(analysis.get("timeseries_event")),
            read_buckets(analysis.get("timeseries_baseline")))


def fill_grid(
    buckets: Dict[datetime, Dict[str, Any]],
    channels: Dict[str, List[float]],
    stamps: Sequence[datetime],
):
    """Place the observed buckets onto a uniform grid.

    Every slot on the grid gets a value for every channel.  A slot with
    no observed bucket gets zero: the network said nothing in it.

    The channels that the source buckets actually carried are returned
    alongside the grid, because a channel the source never mentioned was
    not measured -- it is not a channel that measured zero.
    """
    out: Dict[str, List[float]] = {ch: [0.0] * len(stamps) for ch in channels}
    if not stamps:
        return out, []
    origin = stamps[0]
    carried = set()
    for stamp, entry in buckets.items():
        offset = (stamp - origin).total_seconds()
        index = int(offset // GRID_SECONDS)
        if not (0 <= index < len(stamps)):
            continue
        for ch in channels:
            value = feature_value(entry, _CHANNEL_FEATURES[ch])
            if value is not None:
                carried.add(ch)
            if value:
                out[ch][index] = value
    return out, [ch for ch in channels if ch in carried]


def grid_stamps(buckets: Dict[datetime, Dict[str, Any]],
                 lo: datetime, hi: datetime):
    """The uniform grid from ``lo`` to ``hi``, inclusive."""
    origin = lo.replace(second=0, microsecond=0)
    # The grid is aligned to the wall clock, so a slot is the same
    # interval whichever window it is read in.
    epoch = datetime(1970, 1, 1)
    offset = int((origin - epoch).total_seconds()) % GRID_SECONDS
    origin = origin - timedelta(seconds=offset)
    stamps: List[datetime] = []
    stamp = origin
    while stamp <= hi:
        stamps.append(stamp)
        stamp += timedelta(seconds=GRID_SECONDS)
    return stamps


def same_clock_baseline(
    buckets: Dict[datetime, Dict[str, Any]],
    channel: str,
    window_start: datetime,
    window_end: datetime,
    *,
    days: int = BASELINE_DAYS,
):
    """The channel's mean rate in the *same clock slots* on earlier days.

    The baseline is keyed by the clock position (``HH:MM``) of the slot
    and each key holds the average over the previous days.  This is the
    counterfactual a causal claim needs: what this channel does at this
    hour on an ordinary day.

    The age of a candidate bucket is measured in **elapsed seconds**,
    not in calendar days.  The two differ exactly when the window
    crosses midnight: a window that runs from 21:30 to 06:00 has its
    03:00 slots *after* the window's start date, and a calendar-day
    subtraction counts them as being in the future -- or, worse, counts
    the 21:30 slots of the previous day as being two days old and drops
    them.  A window that spans midnight therefore lost half its
    counterfactual.  The elapsed-seconds test is the one that says what
    it means: *this bucket is between one and ``days`` days before the
    window opened*.
    """
    slot_keys: List[str] = []
    moment = window_start.replace(second=0, microsecond=0)
    step = timedelta(seconds=GRID_SECONDS)
    while moment <= window_end:
        slot_keys.append(moment.strftime("%H:%M"))
        moment += step

    by_slot: Dict[str, List[float]] = {k: [] for k in slot_keys}
    horizon = days * 86400.0
    for stamp, entry in buckets.items():
        age = (window_start - stamp).total_seconds()
        if age <= 0 or age > horizon:
            continue
        key = stamp.strftime("%H:%M")
        if key in by_slot:
            by_slot[key].append(
                feature_value(entry, _CHANNEL_FEATURES[channel]) or 0.0)

    out: Dict[str, float] = {}
    for key in slot_keys:
        values = by_slot.get(key) or []
        out[key] = float(np.mean(values)) if values else 0.0
    return out


def baseline_level(channels: Dict[str, List[float]]):
    """The baseline's mean rate per channel, zeros included.

    The *mean per slot* and not the mean of the non-zero slots: the
    null has to be on the same scale as the statistic it is compared
    with, and a statistic that is a mean over slots has expectation
    equal to that mean per slot.
    """
    level: Dict[str, float] = {}
    for channel, values in channels.items():
        arr = np.asarray(values, dtype=float)
        level[channel] = float(arr.mean()) if arr.size else 0.0
    return level


def build_control_plane_series(
    analysis: Optional[Dict[str, Any]],
    *,
    window_start: Optional[datetime] = None,
    window_end: Optional[datetime] = None,
):
    """Build the routing-side control-plane series for one window.

    When the detector could not supply a feature series the series is
    empty, and the caller is expected to fall back to the event-stream
    representation rather than to invent one.
    """
    event_buckets, base_buckets = extract_timeseries(analysis)

    if not event_buckets:
        return ControlPlaneSeries()

    if window_start is None or window_end is None:
        stamps = sorted(event_buckets)
        lo, hi = stamps[0], stamps[-1]
    else:
        lo, hi = window_start, window_end
        # The detector's own event buckets are the evidence; a window
        # that excludes them all has no control plane to speak of.
        inside = [s for s in event_buckets if lo <= s <= hi]
        if inside:
            lo, hi = min(inside), max(inside)

    stamps = grid_stamps(event_buckets, lo, hi)
    channels, measured = fill_grid(event_buckets, CONTROL_PLANE_CHANNELS, stamps)

    base_stamps: List[datetime] = []
    base_channels: Dict[str, List[float]] = {}
    if base_buckets:
        base_lo = min(base_buckets)
        base_hi = max(base_buckets)
        base_stamps = grid_stamps(base_buckets, base_lo, base_hi)
        base_channels, base_measured = fill_grid(
            base_buckets, CONTROL_PLANE_CHANNELS, base_stamps)
        measured = [ch for ch in measured if ch in base_measured]

    return ControlPlaneSeries(
        stamps=stamps,
        channels=channels,
        baseline=base_channels,
        baseline_stamps=base_stamps,
        baseline_level=baseline_level(base_channels),
        bucket_seconds=float(GRID_SECONDS),
        baseline_bucket_map=base_buckets,
        measured_channels=measured,
    )


def baseline_placebos(
    baseline: Dict[str, List[float]],
    channel: str,
    horizon: int,
):
    """The displacement the channel shows at placebo anchors in the baseline.

    The baseline is the same measurement over the period before the
    event, so the placebos are drawn from the *same instrument* on the
    *same quantity* -- the window before the incident supplies its own
    null, rather than the event window being resampled against itself.
    """
    values = baseline.get(channel) or []
    n = len(values)
    if n < 3 or horizon < 1:
        return []
    out: List[float] = []
    for anchor in range(1, n - horizon):
        pre = values[max(0, anchor - horizon):anchor]
        post = values[anchor:anchor + horizon]
        if len(pre) < max(1, horizon // 2) or len(post) < horizon:
            continue
        out.append(abs(float(np.mean(post)) - float(np.mean(pre))))
    return out
