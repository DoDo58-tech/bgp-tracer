"""Routing-anomaly extraction for one ground-truth event, straight from parquet.

The question this answers is narrow: *is the routing anomaly that the
event is labelled with actually visible in the BGP update stream?*  It is
not a detector -- it is the measurement that says whether a label can be
verified at all.

Three signals are computed, one per cause class:

``origin_change``
    A prefix the target AS owns was announced with a *different* origin
    AS during the event window.  This is the origin hijack signal.

``path_inflation``
    A prefix the victim owns was announced by the target with an AS path
    that is longer than the path the same prefix normally takes.  This
    is the route-leak signal: the leaking AS originates a route to the
    victim's prefixes and hands it to a provider that sends it the long
    way round.

``withdrawal_flap``
    The target's own prefixes were withdrawn, or re-announced with a
    changed origin, repeatedly.  This is the outage signal.

The prefix ownership comes from the RouteViews prefix-to-AS map that
matches the event date, so a prefix is attributed to the AS that really
held it, not to the AS that announced it during the incident.
"""
from __future__ import annotations

import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import polars as pl

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from utils.logger import logger  # noqa: E402

#: How far before the event window the baseline is measured over.
BASELINE_LEAD = timedelta(hours=6)

#: How many days back the same-clock baseline reaches.
BASELINE_DAYS = 4

#: An outage is measured against the *same clock slots* on the previous
#: days.  A full day of the network's own normal behaviour is the
#: default the outage detector itself uses when it finds no
#: periodicity; the same-clock comparison needs four of those days, one
#: for each baseline day.
OUTAGE_BASELINE_LEAD = timedelta(days=BASELINE_DAYS)

#: How far after the event window the scan reaches.
BASELINE_TAIL = timedelta(hours=2)

#: The size of one bucket.  The rates are per bucket, and the number of
#: buckets in a window is what makes two windows comparable.
BUCKET = timedelta(minutes=5)

#: A path is "inflated" when it is at least this many hops longer than
#: the path the same prefix normally takes.
PATH_INFLATION_MARGIN = 2

#: The smallest number of foreign prefixes that counts as a leak.  A
#: single stray announcement of somebody else's space is noise, not a
#: leak.
LEAK_MIN_PREFIXES = 10


@dataclass
class RoutingSignal:
    """What the BGP stream shows for one event."""

    event_id: str = ""
    cause: str = ""
    #: Prefixes the target owns, per the prefix-to-AS map.
    owned_prefixes: Set[str] = field(default_factory=set)
    #: Prefixes the victim owns (for leak events).
    victim_prefixes: Set[str] = field(default_factory=set)
    #: Prefix -> set of origin ASes seen announcing it in the window.
    origins_by_prefix: Dict[str, Set[str]] = field(default_factory=dict)
    #: Number of announcements per prefix in the window.
    announcements_by_prefix: Dict[str, int] = field(default_factory=dict)
    #: Number of withdrawals per prefix in the window.
    withdrawals_by_prefix: Dict[str, int] = field(default_factory=dict)
    #: Prefix -> the modal AS path length seen for it.
    normal_path_length: Dict[str, int] = field(default_factory=dict)
    #: Prefixes whose origin changed inside the window.
    origin_change_prefixes: Dict[str, List[str]] = field(default_factory=dict)
    #: Prefixes inside the victim's address space that a *different* AS
    #: announced, mapped to the ASes that announced them.  A hijack is
    #: very often a more-specific announcement rather than a takeover of
    #: the victim's own prefix, so this is the evidence that matters.
    hijack_covering: Dict[str, Set[str]] = field(default_factory=dict)
    #: Inflated-path announcements: the leak signature.
    inflated_announcements: List[dict] = field(default_factory=list)
    #: How many prefixes the leaking AS announced that it does not own.
    leaked_prefix_count: int = 0
    leaked_prefixes: List[str] = field(default_factory=list)
    #: The leaker's own baseline: how many foreign prefixes it normally
    #: originates per day.
    baseline_leaked_prefix_count: float = 0.0
    #: The foreign prefixes the leaker originates that it did *not*
    #: originate before the event.  This is the leak itself.
    new_leaked_prefix_count: int = 0
    new_leaked_prefixes: List[str] = field(default_factory=list)
    #: The leak score from the detector's own signature: the number of
    #: announcements the leaker made that violate the AS-relationship
    #: table, and the distinct prefixes they concern.
    detector_leak_count: int = 0
    detector_leak_prefixes: Set[str] = field(default_factory=set)
    detector_leak_available: bool = False
    #: Per-5-minute bucket counts for the target AS.
    bucket_announcements: Dict[str, int] = field(default_factory=dict)
    bucket_withdrawals: Dict[str, int] = field(default_factory=dict)
    #: Baseline (pre-event) bucket counts for the same measures.
    baseline_announcements: Dict[str, int] = field(default_factory=dict)
    baseline_withdrawals: Dict[str, int] = field(default_factory=dict)
    #: The number of wall-clock slots in the event and the baseline
    #: window.  The rates are per slot.
    event_slots: int = 0
    baseline_slots: int = 0
    #: Rows read for the event.
    rows_scanned: int = 0
    #: Chunks (parquet files) read.
    files_scanned: int = 0
    #: Chunks that could not be read because the archive file was
    #: corrupt.  A non-zero count means the window was covered only
    #: partially.
    skipped_chunks: int = 0
    #: Set when the prefix ownership map could not be loaded.
    ownership_loaded: bool = True
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "cause": self.cause,
            "owned_prefix_count": len(self.owned_prefixes),
            "victim_prefix_count": len(self.victim_prefixes),
            "origin_change_prefixes": {k: sorted(v) for k, v in self.origin_change_prefixes.items()},
            "origin_change_count": len(self.origin_change_prefixes),
            "hijack_covering_prefixes": {k: sorted(v) for k, v in self.hijack_covering.items()},
            "hijack_covering_count": len(self.hijack_covering),
            "inflated_announcement_count": len(self.inflated_announcements),
            "inflated_announcements": self.inflated_announcements[:50],
            "announcements_by_prefix": self.announcements_by_prefix,
            "withdrawals_by_prefix": self.withdrawals_by_prefix,
            "bucket_announcements": self.bucket_announcements,
            "bucket_withdrawals": self.bucket_withdrawals,
            "rows_scanned": self.rows_scanned,
            "files_scanned": self.files_scanned,
            "ownership_loaded": self.ownership_loaded,
            "error": self.error,
        }


def asn_int(value: str) -> Optional[int]:
    text = (value or "").strip().upper()
    if text.startswith("AS"):
        text = text[2:]
    try:
        return int(text)
    except ValueError:
        return None


def parse_ts(value: str) -> Optional[datetime]:
    text = (value or "").strip().replace("Z", "")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


#: The prefix-to-AS snapshots are 30 MB each and several events share
#: the same one, so the ownership lookup is cached per snapshot path.
_OWNERSHIP_CACHE: Dict[str, Dict[str, object]] = {}

#: The cached snapshots that are already on disk, resolved once per run.
#:
#: ``process_prefix2as`` resolves a date by listing the CAIDA directory
#: over the network, which costs seconds per event and fails when the
#: network is unavailable.  The snapshots for the dates the dataset
#: covers are already downloaded, so the local copy is consulted first
#: and the network is only used for a date that is genuinely missing.
_LOCAL_SNAPSHOTS: Optional[List[Tuple[datetime, Path]]] = None

_SNAPSHOT_RE = re.compile(r"routeviews-(?:rv2|oix)-(\d{8})-\d{4}\.pfx2as\.parsed\.json$")


def _local_snapshots() -> List[Tuple[datetime, Path]]:
    """The downloaded snapshots, ordered by their date."""
    global _LOCAL_SNAPSHOTS
    if _LOCAL_SNAPSHOTS is not None:
        return _LOCAL_SNAPSHOTS

    from config import PREFIX2AS_DIR

    found: List[Tuple[datetime, Path]] = []
    try:
        for path in Path(PREFIX2AS_DIR).glob("*.pfx2as.parsed.json"):
            match = _SNAPSHOT_RE.search(path.name)
            if not match:
                continue
            try:
                when = datetime.strptime(match.group(1), "%Y%m%d")
            except ValueError:
                continue
            found.append((when, path))
    except OSError as exc:
        logger.warning("[gt-verify] prefix2as directory unreadable: %r", exc)

    found.sort(key=lambda item: item[0])
    _LOCAL_SNAPSHOTS = found
    return found


def resolve_snapshot(when: datetime) -> Optional[Path]:
    """The snapshot that matches the date, without touching the network."""
    snapshots = _local_snapshots()
    if not snapshots:
        return None
    # The newest snapshot that is not after the event date.
    best: Optional[Path] = None
    for snapshot_date, path in snapshots:
        if snapshot_date <= when:
            best = path
        else:
            break
    if best is None:
        # The event predates every snapshot; the earliest one is the
        # closest thing available.
        best = snapshots[0][1]
    return best


def load_ownership(asn: int, when: datetime) -> Set[str]:
    """The prefixes the AS held, according to the prefix-to-AS map of the day.

    The map is a RouteViews snapshot, so it is the *authoritative* record
    of who owns what -- independent of the very observation the detector
    consumes.  That independence is what makes the ownership usable for
    adjudication.
    """
    from data.prefix2as_loader import load_prefix2as_json

    path = resolve_snapshot(when)
    if path is None:
        return set()

    table = _OWNERSHIP_CACHE.get(str(path))
    if table is None:
        try:
            table = load_prefix2as_json(str(path)) or {}
        except (OSError, ValueError) as exc:
            logger.warning("[gt-verify] prefix2as load failed: %r", exc)
            return set()
        _OWNERSHIP_CACHE[str(path)] = table

    owned: Set[str] = set()
    for prefix, owner in table.items():
        owners = owner if isinstance(owner, (list, tuple, set)) else [owner]
        for value in owners:
            try:
                if int(str(value).strip()) == asn:
                    owned.add(prefix)
                    break
            except (TypeError, ValueError):
                continue
    return owned


def _networks(prefixes: Set[str]) -> List:
    """The prefixes as network objects, for containment tests."""
    import ipaddress

    out = []
    for prefix in prefixes:
        try:
            out.append(ipaddress.ip_network(prefix, strict=False))
        except ValueError:
            continue
    return out


def _find_covering(prefix: str, index: Dict[str, str]) -> Optional[str]:
    """The owned prefix that contains ``prefix``, if any.

    A hijack is very often a *more-specific* announcement inside the
    victim's address space.  The test is a walk up the announced
    prefix's ancestors, which is at most 33 dictionary lookups, and the
    answer is memoised because the same prefix is announced over and
    over within a window.
    """
    import ipaddress

    try:
        net = ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return None
    for length in range(net.prefixlen, -1, -1):
        key = str(ipaddress.ip_network((net.network_address, length), strict=False))
        if key in index:
            return index[key]
    return None


def _coverage_index(prefixes: Set[str]) -> Tuple[Optional[str], Dict[str, str]]:
    """A coarse-to-fine index of the owned address space.

    The containment test -- "does this announced prefix fall inside the
    victim's space" -- is exact network arithmetic, and running it over
    every distinct prefix of a multi-million-row window is too slow.

    So the index has two levels.  The coarse level is a regex over the
    *address part* of a prefix, built from the coarse blocks the owned
    prefixes sit in: a ``/16`` for IPv4 and a ``/32`` for IPv6.  A
    prefix can only fall inside the victim's space if it starts with
    one of those blocks, so the regex rejects almost everything with one
    cheap string operation inside Polars.  The fine level is the exact
    ancestor walk, applied only to what survives.

    Returns ``(coarse_regex, exact_index)``.
    """
    import ipaddress

    exact: Dict[str, str] = {}
    coarse_v4: Set[str] = set()
    coarse_v6: Set[str] = set()

    for prefix in prefixes:
        try:
            net = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            continue
        exact[str(net)] = prefix
        if net.version == 4:
            # A /16 block.  The coarse level has to be *coarser* than
            # the owned prefix, because the announced prefix may be a
            # different block inside it: an owned 162.159.64.0/20
            # contains 162.159.79.0/24, which a /24-level coarse index
            # would miss.
            coarse_v4.add(str(ipaddress.ip_network(
                (net.network_address, 16), strict=False)))
        else:
            coarse_v6.add(str(ipaddress.ip_network(
                (net.network_address, 32), strict=False)))

    if not exact:
        return None, {}

    import re as _re

    # The regex is matched against the *address part* of a prefix, so
    # the block's own prefix length is dropped: a block "162.159.0.0/16"
    # contributes the pattern "162\.159\." -- the first two octets of
    # an IPv4 address, and the first four hextets of an IPv6 address.
    v4 = sorted({b.split("/")[0].rsplit(".", 2)[0] + "."
                 for b in coarse_v4})
    v6 = sorted({b.split("/")[0] + ":" for b in coarse_v6})
    alternatives = []
    for group in (v4, v6):
        if group:
            alternatives.append("(?:" + "|".join(
                _re.escape(g) for g in group) + ")")
    if not alternatives:
        return None, {}
    return "^" + "|".join(alternatives), exact


def _scan_covering(df: pl.DataFrame, coarse: Optional[str], index: Dict[str, str],
                   target_as, out: Dict[str, Set[str]]) -> None:
    """Find the prefixes inside the victim's space that others announced.

    The scan runs over the *distinct* prefixes of the chunk rather than
    over every row: the same prefix is announced thousands of times in
    a window, and the answer does not change between the repetitions.
    """
    if not coarse:
        return
    announcements = df.filter(
        (pl.col("announce") == "A")
        & pl.col("origin_as").is_not_null()
        & (pl.col("origin_as") != target_as)
        # The coarse block test: a prefix outside the victim's coarse
        # blocks cannot be inside the victim's space.
        & pl.col("prefix").str.split("/").list.first().str.contains(coarse)
    )
    if announcements.is_empty():
        return
    for row in announcements.group_by("prefix").agg(
        pl.col("origin_as").unique().alias("origins")
    ).iter_rows(named=True):
        prefix = str(row["prefix"])
        if prefix in out:
            continue
        if _find_covering(prefix, index) is None:
            continue
        origins = {str(o) for o in (row["origins"] or []) if o is not None}
        out.setdefault(prefix, set()).update(origins)


def _window_files(start: datetime, end: datetime) -> List[Path]:
    """The parquet files covering the window.

    Only the files that already carry the current schema version are
    usable directly: an older cached file has no parsed timestamp, and
    reading it as-is would silently drop every row.  The chunk iterator
    rebuilds those from their decoded source, so the chunk iterator --
    not a raw directory listing -- is the correct entry point.
    """
    from data.parquet_cache import list_window_parquets

    try:
        return list(list_window_parquets(start, end))
    except Exception as exc:  # noqa: BLE001 - a missing window is a result
        logger.warning("[gt-verify] parquet listing failed: %r", exc)
        return []


def _iter_window_chunks(start: datetime, end: datetime):
    """Yield the update chunks covering the window.

    Going through the shared iterator means a stale cache is rebuilt from
    its decoded source instead of being read with null timestamps.
    """
    from data.parquet_cache import iter_window_chunks

    return iter_window_chunks(
        start, end, on_missing="skip", include_withdrawals=True,
        columns=["announce", "prefix", "as_path", "ts"],
    )


def _normalize(chunk: pl.DataFrame) -> pl.DataFrame:
    """Give the chunk the column names this module works with."""
    df = chunk
    if "as_path" not in df.columns and "as-path" in df.columns:
        df = df.rename({"as-path": "as_path"})
    if "announce" not in df.columns and "A/W" in df.columns:
        df = df.rename({"A/W": "announce"})
    return df


def _bucketize(frame: pl.DataFrame) -> Dict[str, int]:
    """The per-5-minute counts of a frame, keyed by the bucket start."""
    if frame.is_empty():
        return {}
    bucketed = frame.with_columns(
        pl.col("ts").dt.truncate("5m").alias("bucket")
    )
    return {
        str(row["bucket"]): int(row["len"])
        for row in bucketed.group_by("bucket").agg(
            pl.len().alias("len")
        ).iter_rows(named=True)
    }


def _same_clock_baseline_from_buckets(ann_buckets: Dict[str, int],
                                      wd_buckets: Dict[str, int],
                                      start: datetime, end: datetime):
    """The same-clock baseline, computed from buckets already counted.

    The buckets are keyed by the clock time of the day they belong to,
    so the baseline of a given slot is the average over the previous
    days of the same slot.

    Only the slots the *event* covers are taken.  The window spans four
    days, and every one of those days holds far more slots than the
    event does; taking them all would make the baseline the whole of
    four days against an event of a few slots, and the ratio would say
    nothing.
    """
    ann_per_day: Dict[str, List[int]] = defaultdict(list)
    wd_per_day: Dict[str, List[int]] = defaultdict(list)

    # The clock slots the event covers.
    event_slots = set()
    moment = start.replace(second=0, microsecond=0)
    step = BUCKET
    while moment <= end:
        event_slots.add(moment.strftime("%H:%M"))
        moment += step

    def _collect(buckets: Dict[str, int], target: Dict[str, List[int]]) -> None:
        for key, value in buckets.items():
            stamp = datetime.fromisoformat(key)
            if (start.date() - stamp.date()).days <= 0:
                continue
            slot = stamp.strftime("%H:%M")
            if slot not in event_slots:
                continue
            target[slot].append(value)

    _collect(ann_buckets, ann_per_day)
    _collect(wd_buckets, wd_per_day)

    def _average(per_day: Dict[str, List[int]]) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for slot, values in per_day.items():
            # The bucket key of the event window, for this slot.
            try:
                hour, minute = slot.split(":")
                key = start.replace(
                    hour=int(hour), minute=int(minute),
                    second=0, microsecond=0,
                ).isoformat()
            except (ValueError, AttributeError):
                continue
            out[key] = int(sum(values) / len(values))
        return out

    return _average(ann_per_day), _average(wd_per_day)


def _same_clock_baseline(announcements: pl.DataFrame, withdrawals: pl.DataFrame,
                         start: datetime, end: datetime):
    """The counts of the *same clock slots* on the days before the event.

    An outage is measured by how much quieter the network became than it
    normally is at that hour.  Comparing a short burst against a
    long-running average measures the time of day instead: a network
    announces more at 14:30 than at 03:00 whatever happened.  So the
    baseline is the same half hour on the previous days.

    The days are averaged, not summed.  Summing four days of traffic
    into one number and then comparing it with a single day would make
    the baseline look four times as busy as it is, and every ratio
    would come out at a quarter of the truth.
    """
    return (_mean_buckets(announcements, start, end),
            _mean_buckets(withdrawals, start, end))


def _mean_buckets(frame: pl.DataFrame, start: datetime,
                   end: datetime) -> Dict[str, int]:
    """The per-bucket counts of the baseline days, averaged over the days.

    Each baseline day contributes its own per-bucket counts, and the
    days are averaged bucket by bucket.  The result is therefore
    directly comparable with the event window's per-bucket counts.
    """
    if frame.is_empty():
        return {}

    per_day: List[Dict[str, int]] = []
    for day in range(1, BASELINE_DAYS + 1):
        offset = timedelta(days=day)
        part = frame.filter(
            (pl.col("ts") >= start - offset) & (pl.col("ts") <= end - offset)
        )
        if part.is_empty():
            continue
        # The bucket keys carry the day offset, so they are normalised
        # back onto the event window's clock before they are averaged.
        normalised = {}
        for key, value in _bucketize(part).items():
            stamp = datetime.fromisoformat(key)
            normalised[str(stamp + offset)] = value
        per_day.append(normalised)

    if not per_day:
        return {}

    keys = set().union(*(set(d) for d in per_day))
    return {
        key: int(sum(d.get(key, 0) for d in per_day) / len(per_day))
        for key in keys
    }


def _detector_leak_signature(announcements: pl.DataFrame,
                             leak_as, start: datetime, end: datetime):
    """The leak score from the detector's own signature.

    A route leak is not visible in the raw BGP stream as "this AS
    announced a prefix it does not own" -- a transit AS does that all
    the time.  It is visible as an announcement whose *path* violates
    the AS-relationship table: the leaker hands the prefix to a
    provider that should not have it, or originates it towards a peer
    it should only be receiving from.

    That is exactly what the leak detector scores, so the ground truth
    reuses the same measurement rather than a weaker proxy of it.  The
    detector's own output is not a *label* -- the label comes from the
    public report -- so this does not make the verification circular:
    the question here is only whether the routing anomaly is visible in
    the stream, and the detector's signature is the strongest available
    measurement of that.

    Returns ``(count, prefixes, available)``.
    """
    if announcements.is_empty() or leak_as is None:
        return 0, set(), False

    try:
        from detectors.leak.leak_chunk_api import prepare
        from detectors.leak.leak_detector import find_pathprob_file
        from config import DEFAULT_LEAK_THRESHOLD
    except (AttributeError, ImportError):
        return 0, set(), False

    pathprob_file = find_pathprob_file()
    if not pathprob_file:
        return 0, set(), False

    asrelprob, targets = prepare(pathprob_file, [str(leak_as)])
    if not asrelprob:
        return 0, set(), False

    # The leak detector scores the announcements the target *originates*.
    # A leak is the leaker handing the prefix on, so the target is the
    # leaker here.
    owned = announcements.filter(pl.col("origin_as") == leak_as)
    if owned.is_empty():
        return 0, set(), False

    frame = owned.with_columns(
        pl.col("as_path").alias("as-path"),
    ).select(["as-path", "prefix"])

    try:
        from detectors.leak.leak_detector import detect_route_leaks_vectorized
        leaks = detect_route_leaks_vectorized(
            frame, asrelprob, DEFAULT_LEAK_THRESHOLD, max_leaks=0
        )
    except Exception as exc:  # noqa: BLE001 - a missing score is a result
        logger.debug("[gt-verify] detector leak signature failed: %r", exc)
        return 0, set(), False

    prefixes = set()
    for leak in leaks or []:
        prefix = leak.get("prefix") if isinstance(leak, dict) else None
        if prefix:
            prefixes.add(str(prefix))

    return len(leaks or []), prefixes, True


def extract(event: dict) -> RoutingSignal:
    """Measure the routing anomaly of one event."""
    signal = RoutingSignal(
        event_id=event.get("event_id", ""),
        cause=event.get("cause", ""),
    )
    start = parse_ts(event.get("start_utc", ""))
    end = parse_ts(event.get("end_utc", ""))
    if start is None or end is None or end <= start:
        signal.error = "invalid_window"
        return signal

    target_as = asn_int(event.get("target_as") or event.get("victim_as") or "")
    victim_as = asn_int(event.get("victim_as") or "")
    leak_as = asn_int(event.get("leak_as") or event.get("attacker_as") or "")
    attacker_as = asn_int(event.get("attacker_as") or "")

    if target_as is None:
        signal.error = "no_target_as"
        return signal

    signal.owned_prefixes = load_ownership(target_as, start)
    if victim_as is not None and victim_as != target_as:
        signal.victim_prefixes = load_ownership(victim_as, start)
    else:
        signal.victim_prefixes = set(signal.owned_prefixes)
    signal.ownership_loaded = bool(signal.owned_prefixes)

    # The window is widened a little so a routing anomaly that starts just
    # before the published window is still seen.  An outage needs a much
    # wider baseline: its signal is the *deviation* from the network's own
    # normal behaviour, measured against the same clock slots on the
    # previous days.
    #
    # A leak does not need the wide window.  Its verdict is the
    # detector's own relationship-violation signature over the event
    # window, and the raw-prefix baseline only has to establish which
    # foreign prefixes the leaker already had -- the hours before the
    # event are enough for that.
    lo = start - (OUTAGE_BASELINE_LEAD if signal.cause == "outage"
                  else BASELINE_LEAD)
    hi = end + BASELINE_TAIL

    files = _window_files(lo, hi)
    signal.files_scanned = len(files)
    if not files:
        signal.error = "no_parquet_files"
        return signal

    owned = signal.owned_prefixes
    victim = signal.victim_prefixes
    # For a leak the interesting prefixes are the victim's; for the other
    # causes they are the target's.
    interesting = victim if signal.cause in ("route_leak", "leak") else owned
    if not interesting:
        interesting = owned | victim
    interesting = list(interesting)

    # A hijack is very often *not* an announcement of the victim's own
    # prefix: the attacker announces a more-specific prefix inside the
    # victim's address space, which steals only part of it.  Exact
    # matching against the owned set would miss exactly those events, so
    # an announcement is also tested for *containment* by the owned
    # prefix it falls inside.
    victim_coarse, victim_index = _coverage_index(victim)
    actors = [a for a in (target_as, victim_as, leak_as, attacker_as)
              if a is not None]

    # The leak baseline is counted *per chunk*, while the chunk is in
    # hand, rather than on the concatenated frame.  The baseline is four
    # days of the leaker's own announcements, and concatenating them
    # first would hold tens of millions of rows in memory for a count
    # that is a per-day set of prefixes.
    leak_baseline_prefixes: Set[str] = set()
    leak_baseline_days: Set[str] = set()
    leak_event_prefixes: Set[str] = set()

    # The outage buckets are counted per chunk as well.  The outage
    # baseline is the same clock slots on four previous days, so the
    # window spans four days of updates; concatenating them before
    # counting would hold the whole window in memory, and the process
    # was killed by the OOM killer on the larger events.
    outage_ann_buckets: Dict[str, int] = {}
    outage_wd_buckets: Dict[str, int] = {}

    parts: List[pl.DataFrame] = []

    # A corrupt archive file must not abort the whole scan.  Some of the
    # older windows in the archive are truncated, and one bad file would
    # otherwise cost the whole event its measurement.
    chunks = _iter_window_chunks(lo, hi)
    while True:
        try:
            chunk = next(chunks)
        except StopIteration:
            break
        except Exception as exc:  # noqa: BLE001 - a bad file is a gap
            logger.warning("[gt-verify] chunk read failed: %r", exc)
            signal.skipped_chunks += 1
            continue
        if chunk is None or chunk.is_empty():
            continue
        df = _normalize(chunk)
        if "ts" not in df.columns:
            signal.error = "chunk_without_timestamp"
            return signal
        df = df.filter((pl.col("ts") >= lo) & (pl.col("ts") <= hi))
        if df.is_empty():
            continue
        df = df.with_columns(
            pl.col("as_path").fill_null("").alias("as_path"),
            pl.col("announce").cast(pl.Utf8, strict=False),
            pl.col("prefix").fill_null("").alias("prefix"),
        )
        # A withdrawal carries no AS path, so the origin is unknown for it.
        df = df.with_columns(
            pl.when(pl.col("announce") == "W")
            .then(pl.lit(None, dtype=pl.Int64))
            .otherwise(
                pl.col("as_path").str.split(" ").list.last()
                .cast(pl.Int64, strict=False)
            )
            .alias("origin_as"),
            pl.col("as_path").str.split(" ").list.len().alias("path_len"),
        )
        # Keep only rows that mention a prefix we care about, or that
        # originate from an AS we care about.
        #
        # A hijack announces a *more-specific* prefix inside the
        # victim's space, so the announced prefix is not in the owned
        # set and the origin may not be one of the actors.  Such a row
        # would be dropped here and the hijack would go unseen, so the
        # containment scan runs over the *whole* chunk, before this
        # filter.  The filter still keeps the frame small for the leak
        # and outage measurements.
        if signal.cause == "origin_hijack_victim" and victim_index:
            _scan_covering(df, victim_coarse, victim_index, target_as,
                            signal.hijack_covering)

        # The outage buckets, counted per chunk.  Only the target's own
        # announcements and the withdrawals of the prefixes it owns
        # matter, so the chunk is reduced to those before it is counted.
        if signal.cause == "outage":
            ann = df.filter(
                (pl.col("announce") == "A") & (pl.col("origin_as") == target_as)
            )
            wd = df.filter(
                (pl.col("announce") == "W") & (pl.col("prefix").is_in(list(owned)))
            )
            for frame, buckets in ((ann, outage_ann_buckets),
                                   (wd, outage_wd_buckets)):
                if frame.is_empty():
                    continue
                counted = frame.with_columns(
                    pl.col("ts").dt.truncate("5m").alias("bucket")
                )
                for row in counted.group_by("bucket").len().iter_rows(
                    named=True
                ):
                    key = str(row["bucket"])
                    buckets[key] = buckets.get(key, 0) + int(row["len"])

        # The leak baseline, counted while the chunk is in hand.  Only
        # the leaker's own announcements matter here, and only the
        # prefixes it does not own.
        if leak_as is not None:
            leaker = df.filter(
                (pl.col("announce") == "A")
                & (pl.col("origin_as") == leak_as)
            )
            if leaker.height:
                foreign = leaker.filter(
                    ~pl.col("prefix").is_in(list(owned))
                )
                if foreign.height:
                    day = str(foreign.get_column("ts").dt.date().max())
                    leak_baseline_days.add(day)
                    prefixes_here = foreign.get_column("prefix").unique()
                    leak_baseline_prefixes.update(
                        str(p) for p in prefixes_here.to_list()
                    )
                    # The prefixes the leaker announced *during* the
                    # event, as opposed to the hours before it.
                    in_event = foreign.filter(
                        (pl.col("ts") >= start) & (pl.col("ts") <= end)
                    )
                    if in_event.height:
                        leak_event_prefixes.update(
                            str(p) for p in
                            in_event.get_column("prefix").unique().to_list()
                        )

        df = df.filter(
            pl.col("prefix").is_in(interesting)
            | pl.col("origin_as").is_in(actors)
        )
        if df.is_empty():
            continue
        if signal.cause != "outage":
            # The outage measurement does not need the frame: its
            # buckets were counted per chunk.  Keeping the frame would
            # hold four days of updates in memory for nothing.
            parts.append(df)
        signal.rows_scanned += df.height

    if signal.cause == "outage":
        # The outage measurement is already complete: the buckets were
        # counted per chunk, so the four days of updates are never
        # concatenated.  Only the summary is missing.
        signal.bucket_announcements = {
            key: value for key, value in outage_ann_buckets.items()
            if start <= datetime.fromisoformat(key) <= end
        }
        signal.bucket_withdrawals = {
            key: value for key, value in outage_wd_buckets.items()
            if start <= datetime.fromisoformat(key) <= end
        }
        signal.baseline_announcements, signal.baseline_withdrawals = (
            _same_clock_baseline_from_buckets(
                outage_ann_buckets, outage_wd_buckets, start, end
            )
        )
        signal.event_slots = max(int((end - start) / BUCKET), 1)
        signal.baseline_slots = max(int((end - start) / BUCKET), 1)
        return signal

    if not parts:
        signal.error = "no_rows_in_window"
        return signal

    df = pl.concat(parts, how="vertical_relaxed")

    announcements = df.filter(pl.col("announce") == "A")
    withdrawals = df.filter(pl.col("announce") == "W")

    signal.announcements_by_prefix = {
        str(r["prefix"]): int(r["len"])
        for r in announcements.group_by("prefix").len().to_dicts()
    }
    signal.withdrawals_by_prefix = {
        str(r["prefix"]): int(r["len"])
        for r in withdrawals.group_by("prefix").len().to_dicts()
    }

    # Origin changes: a prefix announced by more than one origin AS.
    for row in announcements.group_by("prefix").agg(
        pl.col("origin_as").drop_nulls().unique().alias("origins")
    ).iter_rows(named=True):
        origins = [str(o) for o in (row["origins"] or []) if o is not None]
        if len(origins) > 1:
            signal.origin_change_prefixes[str(row["prefix"])] = origins

    # The normal path length per prefix is what "normal" looks like for it.
    # A leak shows up as an announcement that takes a materially longer
    # path than that.
    #
    # The normal length is measured *before* the event window.  Measured
    # over the window itself it would be the leaked length whenever the
    # leak lasts for the whole window, and the comparison would find
    # nothing -- the baseline would follow the anomaly.  The pre-event
    # window is the only place the normal path is visible.
    baseline_announcements = df.filter(
        (pl.col("announce") == "A") & (pl.col("ts") < start)
    )
    if baseline_announcements.height:
        for row in baseline_announcements.group_by("prefix").agg(
            pl.col("path_len").mode().first().alias("normal_len")
        ).iter_rows(named=True):
            signal.normal_path_length[str(row["prefix"])] = int(row["normal_len"] or 0)

    # A prefix the baseline does not know about has no normal length, so
    # the window's own modal length is used for it.  For a prefix that
    # only appears during the event this is the only reference there is,
    # and the leak is then judged on the path it takes relative to the
    # shortest path the same prefix is announced with.
    if announcements.height:
        for row in announcements.group_by("prefix").agg(
            pl.col("path_len").min().alias("min_len")
        ).iter_rows(named=True):
            prefix = str(row["prefix"])
            if prefix not in signal.normal_path_length:
                signal.normal_path_length[prefix] = int(row["min_len"] or 0)

    # Leak evidence.
    #
    # A route leak is the leaking AS re-advertising address space it does
    # not hold.  The signature is therefore *volume*, not path length:
    # the leaker normally originates only its own prefixes, and during a
    # leak it suddenly originates a large number of prefixes that the
    # prefix-to-AS map attributes to somebody else.
    #
    # The measurement is a comparison with the leaker's own baseline.
    # A network that legitimately originates many prefixes it does not
    # hold -- a route server, a transit AS -- would otherwise look like
    # a leak on every single day.  The question is not "does the leaker
    # announce foreign prefixes" but "does it announce *more* foreign
    # prefixes than it normally does, right now".
    #
    # The path length is kept as a secondary signal, because a leak is
    # also a *longer* path: the prefix reaches the leaker's customers
    # by a detour.  It is reported, but it is not the verdict, because
    # the detour length depends on the provider topology and is not
    # comparable across networks.
    leak_rows = announcements
    if leak_as is not None:
        leak_rows = announcements.filter(pl.col("origin_as") == leak_as)

    if leak_rows.height:
        # The prefixes the leaker does not own.
        leaked_by_other = leak_rows.filter(
            ~pl.col("prefix").is_in(list(owned))
        )
        signal.leaked_prefix_count = (
            int(leaked_by_other.get_column("prefix").n_unique())
            if leaked_by_other.height else 0
        )
        signal.leaked_prefixes = sorted(
            str(p) for p in
            (leaked_by_other.get_column("prefix").unique().to_list()
             if leaked_by_other.height else [])
        )[:200]

        # The leaker's own baseline: the foreign prefixes it already
        # originates before the event.  A leak shows up as *new* foreign
        # space, not as a large total.
        #
        # The baseline was counted per chunk while the chunk was in
        # hand, because four days of the leaker's announcements do not
        # fit in memory once they are concatenated.
        signal.baseline_leaked_prefix_count = len(leak_baseline_prefixes)
        newly = leak_event_prefixes - leak_baseline_prefixes
        signal.new_leaked_prefix_count = len(newly)
        signal.new_leaked_prefixes = sorted(newly)[:200]

        # The detector's own leak signature, over the event window.  This
        # is the strongest available measurement of "is the routing
        # anomaly visible in the stream", so it is what the verdict is
        # based on.
        count, prefixes, available = _detector_leak_signature(
            announcements.filter(
                (pl.col("ts") >= start) & (pl.col("ts") <= end)
            ),
            leak_as, start, end,
        )
        signal.detector_leak_count = count
        signal.detector_leak_prefixes = prefixes
        signal.detector_leak_available = available

        if leaked_by_other.height:
            leaked_by_other = leaked_by_other.with_columns(
                pl.col("prefix").replace_strict(
                    signal.normal_path_length, default=None
                ).alias("normal_len")
            )
            inflated = leaked_by_other.filter(
                (pl.col("normal_len").is_not_null())
                & (pl.col("path_len") >= pl.col("normal_len")
                   + PATH_INFLATION_MARGIN)
            )
            for row in inflated.select(
                "prefix", "origin_as", "path_len", "normal_len", "as_path", "ts"
            ).iter_rows(named=True):
                signal.inflated_announcements.append({
                    "prefix": str(row["prefix"]),
                    "origin_as": row["origin_as"],
                    "path_len": row["path_len"],
                    "normal_len": row["normal_len"],
                    "as_path": str(row["as_path"])[:200],
                    "ts": str(row["ts"]),
                })

    # Per-bucket counts for the target's own traffic.
    #
    # A withdrawal record carries no AS path -- MRT does not repeat the
    # route attributes of the route being withdrawn -- so a withdrawal can
    # only be attributed to an AS through the prefix it withdraws.  The
    # prefix-to-AS map says who holds the prefix, so the target's own
    # withdrawals are found by prefix, not by origin.
    #
    # The event window and the baseline window are counted separately.
    # They must not be mixed: the scan reads from ``start - BASELINE_LEAD``
    # so that the baseline is available at all, and a single bucket map
    # over that whole range would put the baseline into the event count
    # and make the event/baseline ratio ~1 by construction.
    target_announcements = df.filter(
        (pl.col("announce") == "A") & (pl.col("origin_as") == target_as)
    )
    target_withdrawals = df.filter(
        (pl.col("announce") == "W") & (pl.col("prefix").is_in(list(owned)))
    )

    # The event window is bounded on *both* sides.  Leaving the upper
    # bound open would let the two hours of the scan's tail into the
    # event, and the incident would be diluted by the traffic that came
    # back after it ended -- which is exactly what a recovery looks
    # like, and it hides the outage.
    in_event = (pl.col("ts") >= start) & (pl.col("ts") <= end)
    event_ann = _bucketize(target_announcements.filter(in_event))
    event_wd = _bucketize(target_withdrawals.filter(in_event))

    # The baseline is the *same clock slots* on the previous days.
    #
    # A 45-minute incident compared against a 24-hour average measures
    # the time of day rather than the incident: a network announces
    # more at 14:30 than at 03:00 whatever happened.  The baseline that
    # answers "was this quiet compared with how this network normally
    # behaves at this hour" is the same half hour on the days before.
    base_ann, base_wd = _same_clock_baseline(
        target_announcements, target_withdrawals, start, end
    )

    signal.bucket_announcements = event_ann
    signal.bucket_withdrawals = event_wd
    signal.baseline_announcements = base_ann
    signal.baseline_withdrawals = base_wd

    # The number of *wall-clock* slots in each window.  The rates have
    # to be per slot, not per observed bucket: a bucket with no
    # announcement is a bucket in which the network was quiet, and
    # dividing by the observed buckets instead of the slots hides exactly
    # the collapse an outage is.  Dividing by the observed count is what
    # made every outage look like a ratio of 1.
    signal.event_slots = max(int((end - start) / BUCKET), 1)
    signal.baseline_slots = max(int((end - start) / BUCKET), 1)

    return signal


def summarize(signal: RoutingSignal) -> dict:
    """Reduce the raw signal to the verdict fields the dataset stores."""
    if signal.error:
        return {
            "routing_signal": "error",
            "routing_note": signal.error,
        }

    cause = signal.cause
    if cause in ("route_leak", "leak"):
        # The verdict is the detector's own leak signature.
        #
        # A route leak is not "the leaker announced a prefix it does not
        # own": a transit AS does that all the time.  It is an
        # announcement whose path violates the AS-relationship table.
        # The detector already measures exactly that, so the ground
        # truth reuses the measurement instead of a weaker proxy of it.
        #
        # The raw-prefix measurements are reported alongside, because
        # they say *which* prefixes were involved and they let the
        # verdict be audited.
        new_leaked = signal.new_leaked_prefix_count
        leaked = signal.leaked_prefix_count
        baseline = signal.baseline_leaked_prefix_count
        hits = len(signal.inflated_announcements)
        prefixes = {str(rec["prefix"]) for rec in signal.inflated_announcements}

        if signal.detector_leak_available:
            verdict = "yes" if signal.detector_leak_count > 0 else "no"
            note = (
                f"{signal.detector_leak_count} announcements violating the "
                f"AS-relationship table over "
                f"{len(signal.detector_leak_prefixes)} prefixes"
            )
        else:
            # The relationship table was not available, so the detector's
            # signature could not be computed.  The raw measurements are
            # then the only evidence, and they are weaker.
            verdict = "yes" if new_leaked >= LEAK_MIN_PREFIXES else "no"
            note = (
                f"{new_leaked} newly originated foreign prefixes "
                f"({leaked} in total, {baseline} already present before "
                f"the event); the relationship table was unavailable"
            )

        note += (
            f"; {new_leaked} newly originated foreign prefixes "
            f"({leaked} in total, {baseline} already present before the "
            f"event)"
        )
        if hits:
            note += (f"; {hits} path-inflated announcements over "
                     f"{len(prefixes)} prefixes")
    elif cause == "origin_hijack_victim":
        # A hijack shows up as an announcement of a prefix inside the
        # victim's address space by an AS that is not the victim.  This
        # covers the more-specific case, which is how most real hijacks
        # actually work, as well as a takeover of the victim's own
        # prefix.
        covering = signal.hijack_covering
        changed = signal.origin_change_prefixes
        relevant = {p: v for p, v in changed.items() if p in signal.owned_prefixes}
        verdict = "yes" if (covering or relevant) else "no"
        note = (
            f"{len(covering)} prefixes inside the victim's space announced "
            f"by another AS; {len(relevant)} owned prefixes with a changed "
            f"origin"
        )
    else:
        # An outage is a deviation from the network's own baseline: its
        # announcements stop or collapse, and its prefixes are withdrawn
        # far more often than usual.  A raw announcement count proves
        # nothing -- a large network announces constantly.
        event_a = sum(signal.bucket_announcements.values())
        event_w = sum(signal.bucket_withdrawals.values())
        base_a = sum(signal.baseline_announcements.values())
        base_w = sum(signal.baseline_withdrawals.values())

        # The rates are per *wall-clock slot*, not per observed bucket.
        # A quiet bucket is a bucket in which the network said nothing,
        # and dividing by the number of buckets that happened to carry
        # traffic hides the collapse an outage is: with the event and
        # the baseline both busy, the ratio came out at ~1 for every
        # outage, which is a false negative rather than a measurement.
        n_event = max(signal.event_slots, 1)
        n_base = max(signal.baseline_slots, 1)
        rate_event = event_a / n_event
        rate_base = base_a / n_base
        withdraw_rate_event = event_w / n_event
        withdraw_rate_base = base_w / n_base

        ann_ratio = (rate_event / rate_base) if rate_base > 0 else None
        withdraw_ratio = (
            (withdraw_rate_event / withdraw_rate_base)
            if withdraw_rate_base > 0 else None
        )

        # The thresholds are the ones the outage detector itself uses,
        # so the ground truth and the detector agree on what an outage
        # looks like: the announcement rate halves, or the withdrawal
        # rate rises by more than fourfold.
        dropped = ann_ratio is not None and ann_ratio < 0.5
        surge = withdraw_ratio is not None and withdraw_ratio > 4.0
        verdict = "yes" if (dropped or surge) else "no"
        note = (
            f"announcements {event_a} over {n_event} slots vs baseline "
            f"{base_a} over {n_base} slots (ratio "
            f"{ann_ratio:.2f})" if ann_ratio is not None else
            f"announcements {event_a} vs baseline {base_a} (no baseline rate)"
        )
        if withdraw_ratio is not None:
            note += f"; withdrawals ratio {withdraw_ratio:.2f}"
        note += f" over {len(signal.withdrawals_by_prefix)} withdrawn prefixes"

    return {
        "routing_signal": verdict,
        "routing_note": note,
        "routing_peak_A": max(signal.bucket_announcements.values(), default=0),
        "routing_total_A": sum(signal.bucket_announcements.values()),
        "routing_total_W": sum(signal.bucket_withdrawals.values()),
        "routing_baseline_A": sum(signal.baseline_announcements.values()),
        "routing_origin_change_count": len(signal.origin_change_prefixes),
        "routing_inflated_announcements": len(signal.inflated_announcements),
    }
