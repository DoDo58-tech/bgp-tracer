"""Control-plane event rate -- the routing-side representation.

The estimator that decides causal *direction* needs a routing-side series
that actually moves when the control plane changes.  The representation
used until now did not have that property, and the reason is worth stating
because it is the substance of the method rather than an implementation
detail.

A BGP anomaly is not a large amplitude on a continuous signal.  A hijack
and a leak differ in *kind*; an outage differs in *direction* (the
control plane goes quiet).  What all three share is that they change
**how many routing messages the collector observes per unit time**.  The
per-event ``severity`` field does not carry this: it is absent on most
detector output, it is constant across the events of one incident, and it
says nothing about how densely the events arrived.

So the routing side is represented as an **observation rate**: the number
of routing observations per bucket.  Three quantities are extracted from
it, and they are the three things an incident can do to the control
plane:

``volume``
    how many observations arrived.  An outage suppresses it (the collector
    stops seeing the prefix's updates); a hijack or a leak amplifies it
    (the misconfiguration multiplies the announcements).

``origin_change``
    how many *origin* changes there were.  A hijack is the only incident
    that moves this channel; a leak and an outage do not.  It is the
    channel that separates the incident *kinds*.

``path_change``
    how many *path* changes there were.  A leak is the only incident that
    moves this channel.

The channels are deliberately **not** summed into one score.  Each one is
carried separately into the vetoes so that a verdict can say *which*
control-plane property changed, and so that a hijack cannot be confirmed
by a path-change signal that belongs to a leak.

The series is **normalised by the baseline**: each bucket's count is
divided by the baseline's median count for the same channel.  A raw
observation rate means little on its own -- "40 messages per bucket" is
quiet for an AS that normally emits 40 000 and loud for one that normally
emits 4 -- but "0.1 times the normal rate" is the same statement for
every AS.  Normalising before the estimator sees the series is what makes
its thresholds a property of the method rather than of the network the
method was pointed at.

The module also exposes the **baseline** series the detector already
computed: the same features over the period before the event.  That
baseline is what makes the exclusivity test a real null instead of a
bootstrap of the event period itself.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

__all__ = [
    "CONTROL_PLANE_CHANNELS",
    "ControlPlaneSeries",
    "build_control_plane_series",
    "extract_timeseries",
]

#: The control-plane channels carried separately into the vetoes.
CONTROL_PLANE_CHANNELS = ("volume", "origin_change", "path_change")

#: The detector feature that carries each channel.
_CHANNEL_FEATURES = {
    "volume": ("announcement_count", "total_messages"),
    "origin_change": ("num_ori_change", "ori_change_rate"),
    "path_change": ("num_path_change", "path_change_rate"),
}


@dataclass
class ControlPlaneSeries:
    """The routing side as a set of per-bucket observation rates.

    ``buckets`` is the shared clock the estimator works on: the routing
    and the traffic side are evaluated on the *same* index set, so a
    bucket index means the same wall-clock interval on both sides.
    """

    stamps: List[datetime] = field(default_factory=list)
    channels: Dict[str, List[float]] = field(default_factory=dict)
    #: The same channels over the period *before* the event, when the
    #: detector could supply it.  This is the null the exclusivity test
    #: draws its placebos from.
    baseline: Dict[str, List[float]] = field(default_factory=dict)
    baseline_stamps: List[datetime] = field(default_factory=list)
    #: The baseline's median count per channel, used to normalise.
    baseline_level: Dict[str, float] = field(default_factory=dict)
    #: The wall-clock gap a bucket is expected to span, in seconds.
    bucket_seconds: float = 300.0

    @property
    def n_buckets(self) -> int:
        return len(self.stamps)

    @property
    def has_baseline(self) -> bool:
        return bool(self.baseline) and any(
            len(v) >= 2 for v in self.baseline.values() if v is not None
        )

    def channel(self, name: str) -> List[float]:
        return self.channels.get(name) or []

    def baseline_channel(self, name: str) -> List[float]:
        return self.baseline.get(name) or []

    def normalised(self, name: str) -> List[float]:
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

    def normalised_baseline(self, name: str) -> List[float]:
        """The baseline window's own channel, on the same scale.

        The baseline is normalised by its own median, so it reads "one"
        wherever the baseline is quiet -- which is what makes the
        event window's displacement comparable to the baseline's own.
        """
        values = self.baseline_channel(name)
        arr = np.asarray(values, dtype=float)
        positive = arr[arr > 0]
        level = float(np.median(positive)) if positive.size else 0.0
        if not level or level <= 0:
            return list(values)
        return [v / level for v in values]

    def as_dict(self) -> Dict[str, Any]:
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


def _to_float(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _feature_value(entry: Dict[str, Any], features: Sequence[str]) -> Optional[float]:
    """The first usable value among ``features`` for one bucket."""
    for key in features:
        val = _to_float(entry.get(key))
        if val is not None:
            return val
    return None


def _parse_stamp(value: Any) -> Optional[datetime]:
    from agents.aea_runtime import parse_timestamp
    return parse_timestamp(value)


def extract_timeseries(
    analysis: Optional[Dict[str, Any]],
) -> Tuple[List[datetime], Dict[str, List[float]], List[datetime], Dict[str, List[float]]]:
    """Pull the control-plane features out of a detector analysis block.

    The detector already buckets the routing observations over the event
    window and over the baseline window and records, per bucket, how many
    announcements and withdrawals there were and how many of them changed
    an origin or a path.  Those buckets *are* the control-plane series;
    the estimator does not need to re-derive them from raw updates.

    Returns ``(stamps, channels, baseline_stamps, baseline_channels)``.
    """
    if not isinstance(analysis, dict):
        return [], {}, [], {}

    def read(block: Any) -> Tuple[List[datetime], Dict[str, List[float]]]:
        if not isinstance(block, dict) or not block:
            return [], {}
        parsed: List[Tuple[datetime, Dict[str, Any]]] = []
        for raw_stamp, entry in block.items():
            if not isinstance(entry, dict):
                continue
            stamp = _parse_stamp(raw_stamp)
            if stamp is None:
                continue
            parsed.append((stamp, entry))
        parsed.sort(key=lambda item: item[0])
        stamps = [stamp for stamp, _ in parsed]
        channels: Dict[str, List[float]] = {}
        for channel, features in _CHANNEL_FEATURES.items():
            values: List[float] = []
            for _, entry in parsed:
                val = _feature_value(entry, features)
                # A bucket with no such observation is zero of that
                # channel, not "missing": the count is the quantity.
                values.append(0.0 if val is None else val)
            channels[channel] = values
        return stamps, channels

    stamps, channels = read(analysis.get("timeseries_event"))
    base_stamps, base_channels = read(analysis.get("timeseries_baseline"))
    return stamps, channels, base_stamps, base_channels


def build_control_plane_series(
    analysis: Optional[Dict[str, Any]],
    *,
    window_start: Optional[datetime] = None,
    window_end: Optional[datetime] = None,
) -> ControlPlaneSeries:
    """Build the routing-side control-plane series for one window.

    When the detector could not supply a feature series the series is
    empty, and the caller is expected to fall back to the event-stream
    representation rather than to invent one.
    """
    stamps, channels, base_stamps, base_channels = extract_timeseries(analysis)

    if window_start is not None and window_end is not None and stamps:
        # Keep only the buckets inside the window the caller asked about,
        # so a detector that scanned a wider period cannot leak the
        # outside into the attribution.
        kept = [i for i, s in enumerate(stamps)
                if window_start <= s <= window_end]
        if kept:
            lo, hi = kept[0], kept[-1]
            stamps = stamps[lo:hi + 1]
            channels = {k: v[lo:hi + 1] for k, v in channels.items()}

    return ControlPlaneSeries(
        stamps=stamps,
        channels={k: list(v) for k, v in channels.items()},
        baseline={k: list(v) for k, v in base_channels.items()},
        baseline_stamps=base_stamps,
        baseline_level=_baseline_level(base_channels),
        bucket_seconds=_bucket_seconds(stamps),
    )


def _baseline_level(baseline_channels: Dict[str, List[float]]) -> Dict[str, float]:
    """The baseline's median count per channel.

    The median, not the mean: a single truncated or duplicated bucket in
    the baseline should not move the reference level.
    """
    level: Dict[str, float] = {}
    for channel, values in baseline_channels.items():
        arr = np.asarray(values, dtype=float)
        arr = arr[arr > 0]
        if arr.size:
            level[channel] = float(np.median(arr))
    return level


def _bucket_seconds(stamps: Sequence[datetime]) -> float:
    """The typical wall-clock gap between consecutive buckets."""
    if len(stamps) < 2:
        return 300.0
    gaps = [(stamps[i + 1] - stamps[i]).total_seconds()
            for i in range(len(stamps) - 1)]
    positive = [g for g in gaps if g > 0]
    return float(np.median(positive)) if positive else 300.0


def baseline_placebos(
    baseline: Dict[str, List[float]],
    channel: str,
    horizon: int,
) -> List[float]:
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
    # Every anchor that leaves a full horizon on both sides.
    for anchor in range(1, n - horizon):
        pre = values[max(0, anchor - horizon):anchor]
        post = values[anchor:anchor + horizon]
        if len(pre) < max(1, horizon // 2) or len(post) < horizon:
            continue
        out.append(abs(float(np.mean(post)) - float(np.mean(pre))))
    return out
