"""Outage feature extraction over the parquet update cache.

The original implementation (``extract_event_features.py``) reads the
decoded MRT text files line by line in Python.  That costs ~17 GB of text
IO and a ``strptime`` call per line for a 24-hour baseline, and it is the
single slowest part of a Phase-1 run.

This module computes the same features from the parquet cache, which
already holds the parsed columns, and it computes them with Polars
expressions instead of a Python loop.

Semantic parity with the text implementation is deliberate:

* the time series key is the 5-minute bucket, ISO-formatted;
* a withdrawal carries no AS path, so the prefix's owner is remembered
  from the announcements seen earlier (``prefix_to_target``);
* a prefix is "flapping" when it was both announced and withdrawn in the
  same bucket;
* the per-prefix path history (for ``num_ori_change``, ``num_longer``,
  ``num_shorter`` and the edit-distance entropy) is carried across
  chunks, because a path change is only visible relative to the previous
  announcement of the same prefix.
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, Iterable, Set

import polars as pl

from utils.logger import logger

BUCKET_MINUTES = 5


def bucket_start(ts: datetime) -> datetime:
    minute = (ts.minute // BUCKET_MINUTES) * BUCKET_MINUTES
    return ts.replace(minute=minute, second=0, microsecond=0)


def entropy(values: list) -> float:
    if not values:
        return 0.0
    counts = Counter(values)
    total = len(values)
    return -sum(
        (count / total) * math.log2(count / total)
        for count in counts.values() if count > 0
    )


def edit_distance(old: list, new: list) -> int:
    """Levenshtein distance over AS-path token lists.

    ``editdistance`` (the C extension the text implementation uses) is
    not guaranteed to be installed; a plain dynamic program over the
    short paths involved is fast enough.
    """
    if old == new:
        return 0
    if not old:
        return len(new)
    if not new:
        return len(old)
    prev = list(range(len(new) + 1))
    for i, a in enumerate(old, start=1):
        cur = [i]
        for j, b in enumerate(new, start=1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a != b)))
        prev = cur
    return prev[-1]


def clean_tokens(path_series: pl.Series) -> pl.Series:
    """Split an AS-path column into a token list without empty entries."""
    return (
        path_series.fill_null("")
        .str.strip_chars()
        .str.split(by=" ")
        .list.eval(pl.element().str.strip_chars().filter(pl.element() != ""))
    )


class ParquetOutageFeatureExtractor:
    """Streaming per-bucket feature extraction over parquet chunks.

    One instance covers one target AS and one contiguous scan.  Call
    ``consume`` for every chunk in chronological order, then ``finalize``.
    """

    def __init__(self, target_as: int):
        self.target_as = str(target_as)
        self._buckets: Dict[str, dict] = {}
        # prefix -> set of message types seen in that bucket, for the
        # flapping metric.
        self._bucket_prefix_types: Dict[str, Dict[str, Set[str]]] = defaultdict(
            lambda: defaultdict(set)
        )
        # prefix -> the target AS that was seen originating it.  A
        # withdrawal has no AS path, so this is the only way to attribute
        # it to the victim.
        self._prefix_to_target: Dict[str, str] = {}
        # prefix -> state of the last announcement, for path-change metrics.
        self._route_state: Dict[str, dict] = {}
        self._rows_seen = 0
        self._rows_relevant = 0

    # ── helpers ────────────────────────────────────────────────────────
    def bucket(self, key: str) -> dict:
        b = self._buckets.get(key)
        if b is None:
            b = {
                "announcement_count": 0,
                "withdrawal_count": 0,
                "total_messages": 0,
                #: Announcements **originated by the target AS itself**.
                #:
                #: ``announcement_count`` counts every announcement that
                #: *involves* the target -- one from a peer it talks to,
                #: one whose path merely passes through it, one about a
                #: prefix it owns.  That is the right measure of how busy
                #: the target is in the collector's eyes, but it is the
                #: wrong measure of whether the target is *operating*:
                #: a network that has stopped announcing its own routes
                #: still receives a flood of updates about other people's
                #: routes.  An outage is the target falling silent, so the
                #: channel that carries it is the target's **own**
                #: announcement rate, measured as the origin AS of the
                #: path.
                "own_announcement_count": 0,
                "own_withdrawal_count": 0,
                "announced_prefixes": set(),
                "withdrawn_prefixes": set(),
                "num_ori_change": 0,
                "num_longer": 0,
                "num_shorter": 0,
                "num_new_A_afterW": 0,
                "num_dup_A": 0,
                "num_dup_W": 0,
                "unique_as_set": set(),
                "peer_as_set": set(),
                "path_lengths": [],
                "edit_distances": [],
                "arrival_intervals": [],
                "last_timestamp": None,
            }
            self._buckets[key] = b
        return b

    # ── main entry point ───────────────────────────────────────────────
    def consume(self, df: pl.DataFrame) -> None:
        """Fold one parquet chunk into the running feature state."""
        if df is None or df.is_empty():
            return

        if "announce" not in df.columns and "A/W" in df.columns:
            df = df.rename({"A/W": "announce"})
        if "as_path" not in df.columns and "as-path" in df.columns:
            df = df.rename({"as-path": "as_path"})
        if "ts" not in df.columns:
            logger.warning("[outage-parquet] chunk without a parsed timestamp; skipped")
            return
        if "announce" not in df.columns:
            logger.warning("[outage-parquet] chunk without an announce column; skipped")
            return

        df = df.filter(pl.col("announce").is_in(["A", "W"]))
        if df.is_empty():
            return

        self._rows_seen += df.height

        tokens = clean_tokens(df.get_column("as_path"))
        peer_as = df.get_column("peer_as").fill_null("")

        # Remember which prefixes the target originates, so a later
        # withdrawal of the same prefix can be attributed to it.  This has
        # to happen *before* the relevance filter: a withdrawal row names
        # no AS at all, so it would otherwise be dropped before the
        # ownership map could attribute it.
        owned = df.filter(
            (pl.col("announce") == "A")
            & (tokens.list.last() == self.target_as)
        )
        for prefix in owned.get_column("prefix").to_list():
            if prefix:
                self._prefix_to_target[prefix] = self.target_as

        # Relevance: the target AS is the peer, or appears in the path, or
        # the prefix is one the target is known to originate.
        owned_prefixes = list(self._prefix_to_target)
        df = df.with_columns(
            tokens.alias("_tokens"),
            (
                (peer_as == self.target_as)
                | tokens.list.contains(self.target_as)
                | pl.col("prefix").is_in(owned_prefixes)
            ).alias("_relevant"),
        )
        df = df.filter(pl.col("_relevant"))
        if df.is_empty():
            return
        self._rows_relevant += df.height

        df = df.with_columns(
            pl.col("ts").dt.truncate(f"{BUCKET_MINUTES}m").alias("_bucket")
        ).sort(["_bucket", "ts"])

        rows = df.select(
            ["_bucket", "ts", "announce", "prefix", "peer_as", "_tokens"]
        ).iter_rows(named=True)

        for row in rows:
            self.consume_row(row)

    def consume_row(self, row: dict) -> None:
        bucket = row["_bucket"]
        key = bucket.isoformat()
        msg_type = row["announce"]
        prefix = row["prefix"]
        tokens = [t for t in (row["_tokens"] or []) if t]
        ts = row["ts"]
        peer_as = row["peer_as"]

        b = self.bucket(key)
        b["total_messages"] += 1
        self._bucket_prefix_types[key][prefix].add(msg_type)

        if b["last_timestamp"] is not None:
            b["arrival_intervals"].append((ts - b["last_timestamp"]).total_seconds())
        b["last_timestamp"] = ts

        if msg_type == "A":
            b["announcement_count"] += 1
            b["announced_prefixes"].add(prefix)
            path_len = len(tokens)
            b["path_lengths"].append(path_len)
            b["unique_as_set"].update(tokens)
            if peer_as:
                b["peer_as_set"].add(peer_as)

            origin_as = tokens[-1] if tokens else None
            # The target's *own* announcement: the origin of the path is
            # the target.  This is the channel that falls silent during
            # an outage.
            if origin_as is not None and str(origin_as) == str(self.target_as):
                b["own_announcement_count"] += 1

            state = self._route_state.setdefault(
                prefix,
                {"last_as_path": None, "last_origin": None, "had_withdraw": False,
                 "withdraw_count": 0},
            )
            if state["had_withdraw"]:
                b["num_new_A_afterW"] += 1
                state["had_withdraw"] = False

            path_str = " ".join(tokens)
            if state["last_as_path"] == path_str:
                b["num_dup_A"] += 1
            if state["last_origin"] is not None and origin_as != state["last_origin"]:
                b["num_ori_change"] += 1
            if state["last_as_path"] is not None:
                old_len = len(state["last_as_path"].split())
                if path_len > old_len:
                    b["num_longer"] += 1
                elif path_len < old_len:
                    b["num_shorter"] += 1
                b["edit_distances"].append(
                    edit_distance(state["last_as_path"].split(), tokens)
                )

            state["last_as_path"] = path_str
            state["last_origin"] = origin_as
        else:
            b["withdrawal_count"] += 1
            b["withdrawn_prefixes"].add(prefix)
            # A withdrawal carries no AS path, so it is attributed to
            # the target through the prefix map: the target announced
            # that prefix, so the target's withdrawal of it is the
            # target's own withdrawal.
            if self._prefix_to_target.get(prefix) == self.target_as:
                b["own_withdrawal_count"] += 1
            state = self._route_state.setdefault(
                prefix,
                {"last_as_path": None, "last_origin": None, "had_withdraw": False,
                 "withdraw_count": 0},
            )
            if state["withdraw_count"] > 0 and state["last_as_path"] is None:
                b["num_dup_W"] += 1
            state["had_withdraw"] = True
            state["withdraw_count"] += 1
            state["last_as_path"] = None

    # ── output ─────────────────────────────────────────────────────────
    def finalize(self) -> Dict[str, dict]:
        """Return ``{bucket_iso: feature_dict}`` for every observed bucket."""
        out: Dict[str, dict] = {}
        for key, b in self._buckets.items():
            announcement_count = b["announcement_count"]
            rate_denominator = announcement_count if announcement_count else 1
            flapping = {
                pfx
                for pfx, types in self._bucket_prefix_types.get(key, {}).items()
                if "A" in types and "W" in types
            }
            out[key] = {
                "announcement_count": announcement_count,
                "withdrawal_count": b["withdrawal_count"],
                "total_messages": b["total_messages"],
                "own_announcement_count": b["own_announcement_count"],
                "own_withdrawal_count": b["own_withdrawal_count"],
                "flapping_prefix_count": len(flapping),
                "ori_change_rate": b["num_ori_change"] / rate_denominator,
                "num_ori_change": b["num_ori_change"],
                "path_change_rate": (b["num_longer"] + b["num_shorter"]) / rate_denominator,
                "dup_A_rate": b["num_dup_A"] / rate_denominator,
                "avg_arrival_interval": (
                    sum(b["arrival_intervals"]) / len(b["arrival_intervals"])
                    if b["arrival_intervals"] else 0
                ),
                "editDis_entropy": entropy(b["edit_distances"]),
                "unique_as_count": len(b["unique_as_set"]),
                "unique_peer_as_count": len(b["peer_as_set"]),
                "avg_path_length": (
                    sum(b["path_lengths"]) / len(b["path_lengths"]) if b["path_lengths"] else 0
                ),
                "max_path_length": max(b["path_lengths"]) if b["path_lengths"] else 0,
                "min_path_length": min(b["path_lengths"]) if b["path_lengths"] else 0,
                "announced_prefix_count": len(b["announced_prefixes"]),
                "withdrawn_prefix_count": len(b["withdrawn_prefixes"]),
                "unique_prefix_count": len(
                    b["announced_prefixes"] | b["withdrawn_prefixes"]
                ),
                "origin_change_count": b["num_ori_change"],
            }
        return out


def extract_timeseries_from_chunks(
    chunks: Iterable[pl.DataFrame],
    target_as: int,
) -> Dict[str, dict]:
    """Convenience wrapper: consume an iterable of chunks, return features."""
    extractor = ParquetOutageFeatureExtractor(target_as)
    for chunk in chunks:
        extractor.consume(chunk)
    return extractor.finalize()
