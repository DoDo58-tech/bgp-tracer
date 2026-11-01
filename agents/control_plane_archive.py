"""Build the control-plane series directly from the update archive.

The detector's cached feature series answers "how busy was the target
AS in the collector's eyes".  For a *causal* measurement that is the
wrong quantity, and the reason is worth stating because it was the
main reason the earlier estimator did not work.

An outage is the target falling **silent**: it stops announcing its own
routes.  While it is silent it keeps receiving a flood of updates about
other people's routes, so a measure of involvement stays roughly flat
through the outage.  The measure that moves is the count of
announcements whose **origin** is the target.

So the control plane for the causal estimator is built here, directly
from the parquet archive, with the target's *own* announcements and
withdrawals counted separately from its involvement in other people's
updates.  The same-clock baseline is built the same way, from the same
archive, over the days before the event.

Building it here rather than from the detector's cached features has
three further advantages:

*   the grid is filled by construction -- a slot in which the archive
    holds no update for the target is a slot in which the target said
    nothing, which is a rate of zero rather than a missing measurement;
*   the counterfactual can use **several** preceding days, because the
    archive holds them, so the null is a distribution over ordinary
    days rather than a single day;
*   the measurement is a *rate per wall-clock slot*, never a rate per
    observed bucket, so a collapse cannot hide behind a denominator
    that shrank with it.

The scan is vectorised in Polars.  A four-day window holds hundreds of
millions of rows, and a row-at-a-time Python loop over them does not
finish in any useful time.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Sequence, Tuple

import polars as pl

from agents.temporal import parse_timestamp

__all__ = [
    "BASELINE_DAYS",
    "CONTROL_GRID_SECONDS",
    "ControlPlaneEvidence",
    "build_control_plane_evidence",
    "read_buckets",
]

#: The wall-clock width of one control-plane slot, in seconds.
CONTROL_GRID_SECONDS = 300

from agents.control_plane import BASELINE_DAYS  # noqa: F401


def read_buckets(block: Any):
    """Parse a detector bucket block into ``{stamp: features}``."""
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


@dataclass
class ControlPlaneEvidence:
    """The control plane, measured on the target's *own* announcements.

    ``slots`` is the uniform wall-clock grid.  ``channels`` holds the
    per-slot counts.  ``baseline`` holds the same channels over the
    preceding days, keyed by the **clock position** (``HH:MM``) rather
    than by the absolute stamp, because the counterfactual a causal
    claim needs is "what this network does at this hour on an ordinary
    day", not "what it did yesterday".
    """

    slots: List[datetime] = field(default_factory=list)
    channels: Dict[str, List[float]] = field(default_factory=dict)
    #: channel -> clock position -> mean rate over the preceding days.
    baseline: Dict[str, Dict[str, float]] = field(default_factory=dict)
    #: channel -> clock position -> the number of days that contributed.
    baseline_days: Dict[str, Dict[str, int]] = field(default_factory=dict)
    #: The **raw** per-slot counts over the whole scanned period, keyed by
    #: absolute stamp.  The baseline above is a function of these and of
    #: the window's start, so keeping the raw counts makes the
    #: counterfactual recomputable without re-reading the archive -- which
    #: matters because the archive scan is the expensive part and the
    #: baseline's definition is the thing that gets fixed.
    raw_counts: Dict[str, Dict[str, float]] = field(default_factory=dict)
    #: The target the series was measured for.
    target_as: str = ""
    #: How many update rows were read.
    rows_scanned: int = 0
    #: How many archive files were read.
    files_scanned: int = 0
    #: How many archive files could not be read.
    skipped_chunks: int = 0
    error: str = ""

    @property
    def n_slots(self):
        return len(self.slots)

    def channel(self, name: str):
        return self.channels.get(name) or []

    def slot_index(self, stamp: datetime):
        if not self.slots:
            return None
        offset = (stamp - self.slots[0]).total_seconds()
        index = int(offset // CONTROL_GRID_SECONDS)
        if not (0 <= index < len(self.slots)):
            return None
        return index

    def baseline_for(self, channel: str,
                     stamps: Sequence[datetime]):
        """The counterfactual rate for each of ``stamps``.

        The clock position of each stamp is looked up in the baseline
        map, so the counterfactual is the *same hour* on an ordinary
        day.
        """
        table = self.baseline.get(channel) or {}
        return [float(table.get(s.strftime("%H:%M"), 0.0)) for s in stamps]

    def baseline_mean(self, channel: str,
                      stamps: Sequence[datetime]):
        values = self.baseline_for(channel, stamps)
        return float(sum(values) / len(values)) if values else 0.0

    def as_dict(self):
        return {
            "target_as": self.target_as,
            "n_slots": self.n_slots,
            "channels": {k: len(v) for k, v in self.channels.items()},
            "rows_scanned": self.rows_scanned,
            "files_scanned": self.files_scanned,
            "skipped_chunks": self.skipped_chunks,
            "start": self.slots[0].isoformat() if self.slots else None,
            "end": self.slots[-1].isoformat() if self.slots else None,
            "error": self.error,
        }

    def to_payload(self):
        """The serialisable form of this evidence.

        The **raw counts** are included, not only the derived baseline.
        The archive scan is the expensive step and the counterfactual's
        definition is the part that gets corrected, so the raw material
        is kept and the baseline is recomputed from it whenever the
        definition changes.
        """
        return {
            "slots": [s.isoformat() for s in self.slots],
            "channels": self.channels,
            "baseline": self.baseline,
            "baseline_days": self.baseline_days,
            "raw_counts": self.raw_counts,
            "target_as": self.target_as,
            "rows_scanned": self.rows_scanned,
            "files_scanned": self.files_scanned,
            "skipped_chunks": self.skipped_chunks,
            "error": self.error,
        }

    @classmethod
    def from_payload(
        cls,
        payload: Dict[str, Any],
        *,
        window_start: Optional[datetime] = None,
        baseline_days: int = BASELINE_DAYS,
    ):
        """Rebuild the evidence from a serialised payload.

        When the payload carries the raw counts, the counterfactual is
        recomputed from them with the *current* definition of "the
        preceding days".  A payload written by an older version, which
        did not keep the raw counts, is rebuilt from its stored baseline
        unchanged -- it cannot be improved without re-reading the
        archive, and silently replacing it with an empty baseline would
        turn a measurement into a refutation.
        """
        evidence = cls(target_as=str(payload.get("target_as") or ""))
        evidence.slots = [datetime.fromisoformat(s)
                          for s in (payload.get("slots") or [])]
        evidence.channels = {k: list(v) for k, v
                             in (payload.get("channels") or {}).items()}
        evidence.rows_scanned = int(payload.get("rows_scanned") or 0)
        evidence.files_scanned = int(payload.get("files_scanned") or 0)
        evidence.skipped_chunks = int(payload.get("skipped_chunks") or 0)
        evidence.error = str(payload.get("error") or "")

        raw = payload.get("raw_counts") or {}
        if raw and window_start is not None:
            counts: Dict[str, Dict[datetime, float]] = {}
            for channel, stamps in raw.items():
                counts[channel] = {
                    datetime.fromisoformat(stamp): float(value)
                    for stamp, value in (stamps or {}).items()
                }
            evidence.raw_counts = raw
            apply_baseline(evidence, counts, window_start, baseline_days)
            return evidence

        evidence.baseline = {k: dict(v) for k, v
                             in (payload.get("baseline") or {}).items()}
        evidence.baseline_days = {k: dict(v) for k, v
                                  in (payload.get("baseline_days") or {}).items()}
        return evidence


def to_control_plane_series(evidence: ControlPlaneEvidence):
    """The archive evidence as the estimator's control-plane series.

    The two representations carry the same measurement in different
    shapes: the evidence keeps the counterfactual as a *map* from clock
    position to rate, while the estimator wants a series on the same
    grid as the event window.  Converting here keeps the estimator
    ignorant of where the measurement came from, so the archive path and
    the detector path are interchangeable behind one interface.

    The baseline period is the *preceding days*, not the event window.
    The placebo null is drawn from it, so it has to be a series over
    those days rather than a counterfactual map over the event's own
    clock positions.
    """
    from agents.control_plane import ControlPlaneSeries

    stamps = list(evidence.slots)
    if not stamps:
        return ControlPlaneSeries()

    window_start = stamps[0]
    all_stamps = sorted({
        datetime.fromisoformat(s)
        for raw in (evidence.raw_counts or {}).values()
        for s in (raw or {})
    })
    baseline_stamps = [s for s in all_stamps if s < window_start]
    baseline_channels = {
        channel: [float(raw.get(stamp.isoformat(), 0.0))
                  for stamp in baseline_stamps]
        for channel, raw in (evidence.raw_counts or {}).items()
    }

    # The bucket map holds every slot the archive measured: the baseline
    # days *and* the event window.  The estimator's counterfactual is
    # built from the slots that precede the window, so the map has to
    # span both.
    #
    # The archive's raw counts record only the slots in which the target
    # said something, so the map has to be *filled in* before it can
    # serve as a counterfactual.  A clock position with no entry is not
    # an unknown rate; it is a slot in which the target said nothing,
    # and the counterfactual at that position is the average over the
    # days on which it also said nothing.  Read sparsely, the
    # counterfactual collapses to zero at most positions, the ratio
    # becomes undefined, and a window that was perfectly measurable
    # reads as unmeasured.
    bucket_map: Dict[datetime, Dict[str, float]] = {}
    measured_stamps = set()
    for channel, raw in (evidence.raw_counts or {}).items():
        for stamp_text, value in raw.items():
            stamp = datetime.fromisoformat(stamp_text)
            bucket_map.setdefault(stamp, {})[channel] = float(value)
            measured_stamps.add(stamp)

    # The slots the archive covered: every five-minute position from the
    # earliest measurement to the end of the event window.
    if measured_stamps:
        origin = min(measured_stamps)
        step = timedelta(seconds=CONTROL_GRID_SECONDS)
        stamp = origin
        while stamp <= max(max(measured_stamps), stamps[-1] if stamps else origin):
            bucket_map.setdefault(stamp, {})
            stamp += step

    for stamp in stamps:
        bucket_map.setdefault(stamp, {})

    level = {
        channel: float(sum(table.values()) / len(table)) if table else 0.0
        for channel, table in evidence.baseline.items()
    }
    return ControlPlaneSeries(
        stamps=stamps,
        channels={k: list(v) for k, v in evidence.channels.items()},
        baseline=baseline_channels,
        baseline_stamps=baseline_stamps,
        baseline_level=level,
        bucket_seconds=float(CONTROL_GRID_SECONDS),
        baseline_bucket_map=bucket_map,
        # The archive counts every one of these channels directly from
        # the update stream, so all of them were measured even when the
        # target said nothing at all.  A silent channel is an
        # observation, not an absence.
        measured_channels=list(evidence.channels),
    )


def series_from_payload(payload: Dict[str, Any], *,
                         window_start: Optional[datetime] = None,
                         baseline_days: int = BASELINE_DAYS):
    """The estimator's series, rebuilt from a serialised archive payload."""
    evidence = ControlPlaneEvidence.from_payload(
        payload, window_start=window_start, baseline_days=baseline_days)
    return to_control_plane_series(evidence)


def normalise_chunk(chunk: pl.DataFrame):
    """Give the chunk the column names this module works with."""
    df = chunk
    if "as_path" not in df.columns and "as-path" in df.columns:
        df = df.rename({"as-path": "as_path"})
    if "announce" not in df.columns and "A/W" in df.columns:
        df = df.rename({"A/W": "announce"})
    return df


def grid_stamps_for(lo: datetime, hi: datetime):
    """The uniform wall-clock grid from ``lo`` to ``hi``, inclusive."""
    origin = lo.replace(second=0, microsecond=0)
    epoch = datetime(1970, 1, 1)
    offset = int((origin - epoch).total_seconds()) % CONTROL_GRID_SECONDS
    origin = origin - timedelta(seconds=offset)
    stamps: List[datetime] = []
    stamp = origin
    while stamp <= hi:
        stamps.append(stamp)
        stamp += timedelta(seconds=CONTROL_GRID_SECONDS)
    return stamps


def count_by_bucket(df: pl.DataFrame, column: str):
    """The per-bucket count of the rows where ``column`` is true."""
    if df.is_empty():
        return {}
    return {
        row["_bucket"]: int(row["n"])
        for row in df.group_by("_bucket").agg(pl.len().alias("n"))
        .iter_rows(named=True)
    }


def build_control_plane_evidence(
    target_as: Any,
    window_start: datetime,
    window_end: datetime,
    *,
    baseline_days: int = BASELINE_DAYS,
    include_withdrawals: bool = True,
):
    """Measure the target's own control-plane activity around a window.

    The event window and the baseline days are read from the same
    archive in one pass, so the two are measured by the same instrument
    over the same files -- which is what makes the comparison between
    them a measurement rather than an artefact of two different reads.
    """
    from data.parquet_cache import iter_window_chunks

    try:
        asn = int(str(target_as).strip().upper().replace("AS", ""))
    except (TypeError, ValueError):
        return ControlPlaneEvidence(target_as=str(target_as),
                                    error="bad_target_as")

    # The scan reaches far enough back to build the counterfactual from
    # several ordinary days.
    lo = window_start - timedelta(days=baseline_days)
    hi = window_end

    evidence = ControlPlaneEvidence(target_as=str(asn))

    # channel -> slot stamp -> count
    counts: Dict[str, Dict[datetime, int]] = {
        "own_volume": {},
        "own_withdrawal": {},
        "volume": {},
        "origin_change": {},
        "path_change": {},
    }

    # The prefixes the target originates, needed to attribute its
    # withdrawals -- a withdrawal carries no AS path.  The set is
    # carried across chunks, so a route the target announced in an
    # earlier file is still recognised.
    owned: set = set()

    try:
        chunks = iter_window_chunks(
            lo, hi, on_missing="skip", include_withdrawals=include_withdrawals,
            columns=["announce", "prefix", "as_path", "ts"],
        )
    except Exception as exc:  # noqa: BLE001 - a missing archive is a result
        evidence.error = f"archive_unavailable:{type(exc).__name__}"
        return evidence

    while True:
        try:
            chunk = next(chunks)
        except StopIteration:
            break
        except Exception as exc:  # noqa: BLE001 - a bad file is a gap
            evidence.skipped_chunks += 1
            continue
        if chunk is None or chunk.is_empty():
            continue
        evidence.files_scanned += 1
        df = normalise_chunk(chunk)
        if "ts" not in df.columns or "announce" not in df.columns:
            continue
        df = df.filter((pl.col("ts") >= lo) & (pl.col("ts") <= hi))
        if df.is_empty():
            continue

        df = df.with_columns(
            pl.col("as_path").fill_null("").alias("as_path"),
            pl.col("announce").cast(pl.Utf8, strict=False),
            pl.col("prefix").fill_null("").alias("prefix"),
            pl.col("ts").dt.truncate("5m").alias("_bucket"),
        ).with_columns(
            pl.when(pl.col("announce") == "W")
            .then(pl.lit(None, dtype=pl.Int64))
            .otherwise(
                pl.col("as_path").str.split(" ").list.last()
                .cast(pl.Int64, strict=False)
            ).alias("origin_as"),
            pl.col("as_path").str.split(" ").list.len().alias("path_len"),
        )
        evidence.rows_scanned += df.height

        announcements = df.filter(pl.col("announce") == "A")
        withdrawals = df.filter(pl.col("announce") == "W")

        # The target's own announcements: the origin of the path is the
        # target.  This is the channel that falls silent during an
        # outage -- the target keeps receiving other people's routes
        # while it stops announcing its own.
        own = announcements.filter(pl.col("origin_as") == asn)
        for bucket, count in count_by_bucket(own, "_bucket").items():
            counts["own_volume"][bucket] = count

        # The target's *involvement*: the announcements whose path
        # mentions it.  This is what the detector's own feature series
        # measures, and it is carried separately so that the two can be
        # compared -- an outage moves the own-announcement channel and
        # leaves the involvement channel roughly flat.
        #
        # The match is literal rather than a regular expression: the
        # scan reads every update in a week, and a regex over hundreds
        # of millions of paths costs more than the rest of the query
        # put together.
        involved = announcements.filter(
            pl.col("as_path").str.contains(str(asn), literal=True))
        for bucket, count in count_by_bucket(involved, "_bucket").items():
            counts["volume"][bucket] = count

        # A withdrawal carries no AS path, so it is attributed to the
        # target through the prefixes the target is seen to originate.
        # The ownership map is carried across chunks, so a route the
        # target announced in an earlier file is still recognised.
        if owned and not withdrawals.is_empty():
            own_wd = withdrawals.filter(
                pl.col("prefix").is_in(list(owned)))
            for bucket, count in count_by_bucket(own_wd, "_bucket").items():
                counts["own_withdrawal"][bucket] = count

        # Origin changes and path inflations are detected against the
        # previous announcement of the *same* prefix.
        #
        # The rows that can possibly matter are the ones whose path
        # mentions the target or whose prefix the target is known to
        # originate.  Everything else cannot produce an origin change
        # *of* the target and cannot be a withdrawal of the target's
        # own route, so it is dropped here -- a four-day window holds
        # hundreds of millions of rows and the reduction is what makes
        # the scan finish.
        relevant = announcements.filter(
            pl.col("as_path").str.contains(str(asn), literal=True)
            | pl.col("prefix").is_in(list(owned))
            | (pl.col("origin_as") == asn)
        )
        if not relevant.is_empty():
            ordered = relevant.sort(["prefix", "ts"])
            previous = ordered.with_columns(
                pl.col("origin_as").shift(1).over("prefix").alias("_prev_origin"),
                pl.col("path_len").shift(1).over("prefix").alias("_prev_len"),
            )
            origin_changed = previous.filter(
                pl.col("_prev_origin").is_not_null()
                & pl.col("origin_as").is_not_null()
                & (pl.col("_prev_origin") != pl.col("origin_as"))
            )
            for bucket, count in count_by_bucket(origin_changed,
                                                  "_bucket").items():
                counts["origin_change"][bucket] = count

            path_inflated = previous.filter(
                pl.col("_prev_len").is_not_null()
                & (pl.col("path_len") >= pl.col("_prev_len") + 2)
            )
            for bucket, count in count_by_bucket(path_inflated,
                                                  "_bucket").items():
                counts["path_change"][bucket] = count

            # The prefixes the target originates are needed to attribute
            # its withdrawals, and a withdrawal carries no AS path.
            own_prefixes = (
                relevant.filter(pl.col("origin_as") == asn)
                .get_column("prefix").unique().to_list()
            )
            owned.update(str(p) for p in own_prefixes)

    if not evidence.rows_scanned:
        evidence.error = evidence.error or "no_rows_in_window"
        return evidence

    # The event window's grid, filled.
    slots = grid_stamps_for(window_start, window_end)
    evidence.slots = slots
    evidence.channels = {
        channel: [float(counts[channel].get(stamp, 0)) for stamp in slots]
        for channel in counts
    }

    # The raw counts are kept so that the counterfactual below -- and any
    # later correction to how the counterfactual is defined -- can be
    # recomputed without reading the archive again.
    evidence.raw_counts = {
        channel: {stamp.isoformat(): float(value)
                  for stamp, value in channel_counts.items()}
        for channel, channel_counts in counts.items()
    }

    apply_baseline(evidence, counts, window_start, baseline_days)
    return evidence


def apply_baseline(
    evidence: ControlPlaneEvidence,
    counts: Dict[str, Dict[datetime, float]],
    window_start: datetime,
    baseline_days: int,
):
    """Fill the evidence's counterfactual from the raw per-slot counts.

    The counterfactual is the same clock position on the earlier days.
    Each day contributes its own per-slot count, and the days are
    averaged slot by slot, so the result is directly comparable with
    the event window's per-slot counts.

    The age of a candidate is measured in **elapsed seconds**, not in
    calendar days.  The two differ exactly when the window crosses
    midnight: the 03:00 slot of the *same* calendar date as the
    window's start is, physically, the previous day's 03:00, and it is
    the nearest counterfactual -- but a calendar-day subtraction calls
    it "zero days old" and drops it, while a slot four days earlier
    survives.  The window then loses its most relevant day and keeps
    its least relevant one.
    """
    horizon = baseline_days * 86400.0
    for channel in counts:
        per_slot: Dict[str, List[float]] = {}
        day_hits: Dict[str, int] = {}
        for stamp, value in counts[channel].items():
            age = (window_start - stamp).total_seconds()
            if age <= 0 or age > horizon:
                continue
            key = stamp.strftime("%H:%M")
            per_slot.setdefault(key, []).append(float(value))
            day_hits[key] = day_hits.get(key, 0) + 1
        evidence.baseline[channel] = {
            key: float(sum(vals) / len(vals)) for key, vals in per_slot.items()
        }
        evidence.baseline_days[channel] = day_hits
