"""Cache resolution must pick the newest measurement of a window.

A cache file is a measurement of one window taken at one point in time.
The same window can exist under more than one filename spelling (the
writer emits ``2025-08-10T1430`` when the start time carries a colon and
``2025-08-10_1430`` when it does not), and a re-run leaves the older
file behind.  Both encode an *exact* window match, so the resolver has
to break the tie deliberately.

It used to break it by sort order, which put the stale file first: the
evaluation then scored a detector measurement from before the withdrawal
fix while reporting it as current.  That is a silent evaluation bug, so
the tie-break is now by modification time and is covered here.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from agents.cache_resolution import resolve_cache


def write_cache(path: Path, marker: str):
    path.write_text(
        json.dumps({"asn": "16509", "marker": marker}), encoding="utf-8"
    )


def test_exact_match_prefers_the_newest_file(tmp_path):
    stale = tmp_path / "quick_16509_2025-08-10T1430_2025-08-10T1515.json"
    fresh = tmp_path / "quick_16509_2025-08-10_1430_2025-08-10_1515.json"
    write_cache(stale, "stale")
    time.sleep(0.01)
    write_cache(fresh, "fresh")
    os.utime(stale, (1000, 1000))
    os.utime(fresh, (2000, 2000))

    match = resolve_cache(
        "16509", "2025-08-10 14:30:00", "2025-08-10 15:15:00",
        tmp_path, allow_same_date=False,
    )

    assert match is not None
    assert match.kind == "exact"
    assert match.path == fresh


def test_overlap_match_prefers_the_newest_file(tmp_path):
    stale = tmp_path / "quick_16509_2025-08-10_1430_2025-08-10_1515.json"
    fresh = tmp_path / "quick_16509_2025-08-10_1440_2025-08-10_1530.json"
    write_cache(stale, "stale")
    time.sleep(0.01)
    write_cache(fresh, "fresh")
    os.utime(stale, (1000, 1000))
    os.utime(fresh, (2000, 2000))

    match = resolve_cache(
        "16509", "2025-08-10 14:45:00", "2025-08-10 15:00:00",
        tmp_path, allow_same_date=False,
    )

    assert match is not None
    assert match.path == fresh


def test_a_single_candidate_is_still_resolved(tmp_path):
    only = tmp_path / "quick_16509_2025-08-10_1430_2025-08-10_1515.json"
    write_cache(only, "only")

    match = resolve_cache(
        "16509", "2025-08-10 14:30:00", "2025-08-10 15:15:00",
        tmp_path, allow_same_date=False,
    )

    assert match is not None
    assert match.path == only
