"""Chunk-level leak detection, reusable from a shared update scan.

The leak detector used to own the whole scan: it opened the update
stream, filtered the announcements, and scored them.  That made it
impossible to share the scan with the other detectors, so an event read
the same window three times.

This module separates the two halves:

* :func:`prepare` loads the AS-relationship probability table once.
* :func:`consume_chunk` scores one chunk of announcements.
* :func:`finalize` assembles the result.

The scoring itself is unchanged -- it is the same
``detect_route_leaks_vectorized`` call on the same filtered frame -- so
the numbers a shared scan produces match the numbers the standalone
detector produces.
"""
from __future__ import annotations

import gc
from typing import Iterable, List, Optional, Sequence

import polars as pl

from utils.logger import logger


def prepare(pathprob_file: str, target_asns: Optional[Sequence[str]] = None):
    """Load the relationship table and the target filter.

    Returns ``(asrelprob, target_asns_set)`` or ``(None, None)`` when the
    table is missing.
    """
    from detectors.leak.leak_detector import read_prob

    asrelprob = read_prob(pathprob_file)
    if len(asrelprob) == 0:
        logger.error("Failed to load AS relationship probabilities")
        return None, None
    targets = {str(a) for a in (target_asns or [])}
    return asrelprob, targets


def filter_target_announcements(
    df_chunk: pl.DataFrame,
    target_asns: set,
):
    """Reduce a chunk to the announcements the leak detector scores.

    A path that merely *transits* the target AS is normal traffic.  A
    leak is the target originating a route and that route taking a longer
    path than the provider relationship allows.  Keeping only the paths
    the target actually originates cuts the candidate set from every
    transit announcement to the target's own routes, which is what stops
    the detector from saturating at its 5000-event cap on every window.

    Returns ``(announcements, filtered_ann, total, filtered, origin)``.
    """
    announcements = df_chunk.filter(pl.col("A/W") == "A").select(
        ["as-path", "prefix", "timestamp", "origin"]
    )
    if announcements.is_empty():
        return announcements, announcements, 0, 0

    total_announcements = len(announcements)
    filtered_ann = announcements
    filtered_count = 0
    origin_count = 0

    if target_asns:
        # Pre-split as-path into a list column so .list.contains() can
        # do exact-token matching.
        if "as_path_tokens" not in announcements.columns:
            announcements = announcements.with_columns(
                pl.col("as-path").str.split(by=" ").alias("as_path_tokens")
            )
        mask = None
        for _target_asn in target_asns:
            m = announcements["as_path_tokens"].list.contains(_target_asn)
            mask = m if mask is None else (mask | m)
        filtered_ann = announcements.filter(mask)
        filtered_count = len(filtered_ann)

        # The mask is evaluated on filtered_ann, not on announcements:
        # announcements still holds every path, so a mask built there
        # has a different length than the frame it is applied to.
        _origin_is_target = None
        for _target_asn in target_asns:
            m = filtered_ann["as_path_tokens"].list.last() == _target_asn
            _origin_is_target = m if _origin_is_target is None else (
                _origin_is_target | m
            )
        if _origin_is_target is not None:
            filtered_ann = filtered_ann.filter(_origin_is_target)
            origin_count = len(filtered_ann)

    return announcements, filtered_ann, total_announcements, filtered_count, origin_count


def consume_chunk(
    df_chunk: pl.DataFrame,
    asrelprob: dict,
    threshold: float,
    target_asns: set,
):
    """Score one chunk.  Returns the counters and the leak records."""
    from detectors.leak.leak_detector import detect_route_leaks_vectorized

    if df_chunk is None or df_chunk.is_empty():
        return {
            "total_announcements": 0,
            "filtered_announcements": 0,
            "leak_origin_announcements": 0,
            "leaks": [],
        }

    if "A/W" not in df_chunk.columns and "announce" in df_chunk.columns:
        df_chunk = df_chunk.rename({"announce": "A/W"})
    if "as-path" not in df_chunk.columns and "as_path" in df_chunk.columns:
        df_chunk = df_chunk.rename({"as_path": "as-path"})

    announcements, filtered_ann, total, filtered, origin = filter_target_announcements(
        df_chunk, target_asns
    )
    del df_chunk
    gc.collect()

    if filtered_ann.is_empty():
        del announcements, filtered_ann
        gc.collect()
        return {
            "total_announcements": total,
            "filtered_announcements": filtered,
            "leak_origin_announcements": origin,
            "leaks": [],
        }

    leaks = detect_route_leaks_vectorized(filtered_ann, asrelprob, threshold, max_leaks=0)
    del announcements, filtered_ann
    gc.collect()

    return {
        "total_announcements": total,
        "filtered_announcements": filtered,
        "leak_origin_announcements": origin,
        "leaks": leaks,
    }


def finalize(
    chunk_results: Iterable[dict],
    max_leaks: int = 5000,
):
    """Assemble the per-chunk results into the detector's output shape."""
    all_leaks: List[dict] = []
    total_leak_count = 0
    total_announcements = 0
    filtered_announcements = 0
    leak_origin_announcements = 0

    for res in chunk_results:
        total_leak_count += len(res.get("leaks") or [])
        total_announcements += res.get("total_announcements", 0)
        filtered_announcements += res.get("filtered_announcements", 0)
        leak_origin_announcements += res.get("leak_origin_announcements", 0)
        if max_leaks > 0 and len(all_leaks) >= max_leaks:
            continue
        remaining = max_leaks - len(all_leaks) if max_leaks > 0 else len(res.get("leaks") or [])
        if remaining > 0:
            all_leaks.extend((res.get("leaks") or [])[:remaining])

    truncated = bool(max_leaks > 0 and total_leak_count > len(all_leaks))
    return {
        "route_leaks": all_leaks,
        "leak_count": len(all_leaks),
        "total_detected": total_leak_count,
        "truncated": truncated,
        "truncation_limit": max_leaks if truncated else None,
        "total_announcements": total_announcements,
        "filtered_announcements": filtered_announcements,
        "leak_origin_announcements": leak_origin_announcements,
    }
