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

#: How many days before the event the counterfactual reaches.
BASELINE_DAYS = 4


def read_buckets(block: Any) -> Dict[datetime, Dict[str, Any]]:
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
    def n_slots(self) -> int:
        return len(self.slots)

    def channel(self, name: str) -> List[float]:
        return self.channels.get(name) or []

    def slot_index(self, stamp: datetime) -> Optional[int]:
        if not self.slots:
            return None
        offset = (stamp - self.slots[0]).total_seconds()
        index = int(offset // CONTROL_GRID_SECONDS)
        if not (0 <= index < len(self.slots)):
            return None
        return index

    def baseline_for(self, channel: str,
                     stamps: Sequence[datetime]) -> List[float]:
        """The counterfactual rate for each of ``stamps``.

        The clock position of each stamp is looked up in the baseline
        map, so the counterfactual is the *same hour* on an ordinary
        day.
        """
        table = self.baseline.get(channel) or {}
        return [float(table.get(s.strftime("%H:%M"), 0.0)) for s in stamps]

    def baseline_mean(self, channel: str,
                      stamps: Sequence[datetime]) -> float:
        values = self.baseline_for(channel, stamps)
        return float(sum(values) / len(values)) if values else 0.0

    def as_dict(self) -> Dict[str, Any]:
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


def _normalise(chunk: pl.DataFrame) -> pl.DataFrame:
    """Give the chunk the column names this module works with."""
    df = chunk
    if "as_path" not in df.columns and "as-path" in df.columns:
        df = df.rename({"as-path": "as_path"})
    if "announce" not in df.columns and "A/W" in df.columns:
        df = df.rename({"A/W": "announce"})
    return df


def _grid(lo: datetime, hi: datetime) -> List[datetime]:
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


def _count_by_bucket(df: pl.DataFrame, column: str) -> Dict[datetime, int]:
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
) -> ControlPlaneEvidence:
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
        "involved_volume": {},
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
        df = _normalise(chunk)
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
        for bucket, count in _count_by_bucket(own, "_bucket").items():
            counts["own_volume"][bucket] = count

        # The target's *involvement*: the announcements whose path
        # mentions it.  This is what the detector's own feature series
        # measures, and it is carried separately so that the two can be
        # compared -- an outage moves the own-announcement channel and
        # leaves the involvement channel roughly flat.
        involved = announcements.filter(
            pl.col("as_path").str.contains(str(asn)))
        for bucket, count in _count_by_bucket(involved, "_bucket").items():
            counts["involved_volume"][bucket] = count

        # A withdrawal carries no AS path, so it is attributed to the
        # target through the prefixes the target is seen to originate.
        # The ownership map is carried across chunks, so a route the
        # target announced in an earlier file is still recognised.
        if owned and not withdrawals.is_empty():
            own_wd = withdrawals.filter(
                pl.col("prefix").is_in(list(owned)))
            for bucket, count in _count_by_bucket(own_wd, "_bucket").items():
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
            pl.col("as_path").str.contains(str(asn))
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
            for bucket, count in _count_by_bucket(origin_changed,
                                                  "_bucket").items():
                counts["origin_change"][bucket] = count

            path_inflated = previous.filter(
                pl.col("_prev_len").is_not_null()
                & (pl.col("path_len") >= pl.col("_prev_len") + 2)
            )
            for bucket, count in _count_by_bucket(path_inflated,
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
    slots = _grid(window_start, window_end)
    evidence.slots = slots
    evidence.channels = {
        channel: [float(counts[channel].get(stamp, 0)) for stamp in slots]
        for channel in counts
    }

    # The counterfactual: the same clock position on the earlier days.
    # Each day contributes its own per-slot count, and the days are
    # averaged slot by slot, so the result is directly comparable with
    # the event window's per-slot counts.
    for channel in counts:
        per_slot: Dict[str, List[float]] = {}
        day_hits: Dict[str, int] = {}
        for stamp, value in counts[channel].items():
            delta = (window_start.date() - stamp.date()).days
            if delta <= 0 or delta > baseline_days:
                continue
            key = stamp.strftime("%H:%M")
            per_slot.setdefault(key, []).append(float(value))
            day_hits[key] = day_hits.get(key, 0) + 1
        evidence.baseline[channel] = {
            key: float(sum(vals) / len(vals)) for key, vals in per_slot.items()
        }
        evidence.baseline_days[channel] = day_hits

    return evidence
