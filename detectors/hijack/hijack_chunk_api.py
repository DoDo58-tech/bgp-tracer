"""Chunk-level hijack detection, reusable from a shared update scan.

``detect_hijacks_batch`` owns the whole scan today: it streams the
updates, converts each chunk to records, and hands them to a worker.
That makes the stream impossible to share with the leak and outage
detectors, so an event reads the same window three times.

This module exposes the two halves of that work:

* :func:`prepare` resolves the target AS list, the prefix ownership map
  and the covered-subnet set -- everything that depends on the AS
  relationships rather than on the updates themselves.
* :func:`consume_chunk` scores one chunk of announcements.
* :func:`finalize` folds the per-chunk alerts into the per-AS result.

The scoring is the same ``process_chunk_worker`` call the batch
detector makes, so the alerts a shared scan produces match the alerts
the standalone detector produces.

``skip_forge`` is honoured as it is elsewhere: the forge (MITM) variant
is not evaluated at the moment.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Sequence

import polars as pl

from utils.logger import logger

CHUNK_COLUMNS = ["prefix", "as-path", "A/W", "timestamp"]


def prepare(
    target_as_list: Sequence[str],
    prefix_to_as: Dict[str, object],
    covered_subnet_set: Sequence[str],
    as_relationships_data: Optional[dict] = None,
    skip_forge: bool = True,
    prefixes_by_as: Optional[Dict[str, Sequence[str]]] = None,
):
    """Resolve everything the per-chunk worker needs.

    Returns the params dict that :func:`consume_chunk` forwards to the
    worker, plus the per-AS result skeleton.

    ``prefixes_by_as`` maps each target AS to the prefixes it owns.  It
    has to be the *complete* set, not the prefixes seen in a chunk: the
    worker trims the prefix-to-AS map down to the chunk, and without the
    complete ownership set a prefix the target owns but does not
    re-announce in this chunk would be invisible to the detector.
    """
    cleaned_as_list = [str(a).replace("AS", "").replace("as", "") for a in target_as_list]
    cleaned_as_set = set(cleaned_as_list)

    if prefixes_by_as is None:
        prefixes_by_as = {}
        for asn in cleaned_as_list:
            owned = set()
            for prefix, owner in (prefix_to_as or {}).items():
                owners = owner if isinstance(owner, (list, tuple, set)) else [owner]
                if any(str(o) in cleaned_as_set for o in owners):
                    owned.add(prefix)
            prefixes_by_as[asn] = owned

    union_target_prefixes = set()
    for asn in cleaned_as_list:
        union_target_prefixes |= set(prefixes_by_as.get(asn, ()))

    params = {
        # The worker wraps these in a set itself, so they are handed over
        # as the collections they are: a set of prefixes and a set of
        # covered subnets.
        "union_target_prefixes": union_target_prefixes,
        "covered_subnet_set": set(covered_subnet_set),
        "cleaned_as_set": cleaned_as_set,
        "cleaned_as_list": cleaned_as_list,
        "skip_forge_detection": skip_forge,
        "prefix_to_as": prefix_to_as or {},
        "prefixes_by_as": prefixes_by_as,
        "as_relationships_data": as_relationships_data or {},
    }

    results = {
        asn: {
            "origin_hijacked": [],
            "origin_hijacking": [],
            "forge_hijack": [],
            "forge_hijacking": [],
            "total_announcements": 0,
        }
        for asn in cleaned_as_list
    }
    return {"params": params, "results": results, "cleaned_as_list": cleaned_as_list}


def consume_chunk(
    df_chunk: pl.DataFrame,
    prepared: dict,
):
    """Score one chunk of announcements.  Returns the alerts it produced."""
    from detectors.hijack.hijack_detector import process_chunk_worker

    if df_chunk is None or df_chunk.is_empty():
        return []

    if "A/W" not in df_chunk.columns and "announce" in df_chunk.columns:
        df_chunk = df_chunk.rename({"announce": "A/W"})
    if "as-path" not in df_chunk.columns and "as_path" in df_chunk.columns:
        df_chunk = df_chunk.rename({"as_path": "as-path"})

    keep = [c for c in CHUNK_COLUMNS if c in df_chunk.columns]
    records = df_chunk.select(keep).to_dicts()
    if not records:
        return []

    params = dict(prepared["params"])

    # The prefix-to-AS map the worker uses decides whether a prefix is
    # owned by the target, owned by someone else, or simply unknown.  It
    # also feeds the sub-prefix trie, so it has to be the *complete* map:
    # a map trimmed to the prefixes in this chunk would make the covering
    # prefix of an announced prefix disappear, and the announcement would
    # be read as "unknown" instead of "owned by someone else" -- which
    # turns a victim's route into a false accusation against the target.
    #
    # The trimming exists for the batch detector, where the map is
    # pickled to a worker process.  The shared scan runs in one process,
    # so the full map costs nothing.
    params["prefix_to_as_subset"] = params.get("prefix_to_as") or {}
    try:
        return process_chunk_worker((records, params)) or []
    except (AttributeError, KeyError, TypeError) as exc:
        # A silent skip here would look like "no hijacks detected", which
        # is exactly the kind of false negative that hides an attack.
        logger.warning(
            "[hijack-chunk] worker failed on a chunk with %d rows: %r",
            len(records), exc,
        )
        return []


def finalize(prepared: dict, chunk_alerts: Sequence[dict]):
    """Fold the per-chunk alerts into the per-AS result.

    The alerts have to be folded in chronological order so that the
    retained sample reads in the order the events happened.
    """
    from detectors.hijack.hijack_detector import merge_chunk_alerts
    from detectors.hijack.hijack_analyzer import StreamingAnomalyAggregator

    results = prepared["results"]
    for asn in results:
        results[asn]["_aggregator"] = StreamingAnomalyAggregator()

    for alerts in chunk_alerts:
        if alerts:
            merge_chunk_alerts(results, alerts)

    return results
