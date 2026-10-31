#!/usr/bin/env python3
"""Build the parquet cache for a set of windows, in parallel.

The ground-truth build reads the same four-day baseline for every outage
event, and the archive stores those windows as compressed MRT files.  The
cache builder decodes one file at a time, which is slow enough that the
build spends most of its time decoding rather than measuring.

This script does the decoding up front, across many processes, so the
build itself reads only parquet.  It is a cache warmer, not a detector:
it changes no measurement and no verdict.
"""

from __future__ import annotations

import argparse
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def build_one(stamp: str) -> tuple[str, str]:
    """Build the parquet for one window stamp.

    Returns ``(stamp, status)`` where status is ``cached``, ``missing``
    or ``failed``.
    """
    try:
        from data.parquet_cache import (
            PARQUET_DIR,
            UPDATES_ROOT,
            DECODED_DIR,
            ensure_parquet,
            is_cache_valid,
        )
    except Exception as exc:  # noqa: BLE001
        return stamp, f"import_error:{exc!r}"

    parquet = PARQUET_DIR / f"updates.{stamp}.parquet"
    txt = DECODED_DIR / f"updates.{stamp}.txt"
    gz = UPDATES_ROOT / f"updates.{stamp}.gz"

    for src in (txt, gz):
        if not src.exists() or src.stat().st_size == 0:
            continue
        if parquet.exists() and is_cache_valid(parquet, src):
            return stamp, "cached"
        try:
            built = ensure_parquet(src)
        except Exception as exc:  # noqa: BLE001
            return stamp, f"failed:{exc!r}"
        if built is not None:
            return stamp, "cached"
        return stamp, "failed:empty"

    return stamp, "missing"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--start", required=True,
        help="The first window, as YYYY-MM-DD HH:MM.",
    )
    parser.add_argument(
        "--end", required=True,
        help="The last window, as YYYY-MM-DD HH:MM.",
    )
    parser.add_argument(
        "--days-before", type=int, default=0,
        help="Also warm the same clock slots on the previous N days.",
    )
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()

    start = datetime.strptime(args.start, "%Y-%m-%d %H:%M")
    end = datetime.strptime(args.end, "%Y-%m-%d %H:%M")

    stamps: list[str] = []
    for day_offset in range(args.days_before + 1):
        day = start - timedelta(days=day_offset)
        cur = day.replace(
            minute=(day.minute // 5) * 5, second=0, microsecond=0
        )
        while cur <= (end - timedelta(days=day_offset)):
            stamps.append(cur.strftime("%Y%m%d.%H%M"))
            cur += timedelta(minutes=5)

    # The same stamp can appear twice when the window is longer than a
    # day; it only needs building once.
    stamps = sorted(set(stamps))
    print(f"warming {len(stamps)} windows with {args.workers} workers",
          flush=True)

    counts: dict[str, int] = {}
    done = 0
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(build_one, stamp): stamp for stamp in stamps}
        for future in as_completed(futures):
            try:
                stamp, status = future.result()
            except Exception as exc:  # noqa: BLE001 - one bad file is not fatal
                # A worker can be killed outright (the kernel, an
                # out-of-memory kill).  The window is simply not warmed
                # this time round; the reader will build it on demand.
                status = f"failed:{exc!r}"
            key = status.split(":")[0]
            counts[key] = counts.get(key, 0) + 1
            done += 1
            if done % 200 == 0:
                print(f"  {done}/{len(stamps)} {counts}", flush=True)

    print(f"done: {counts}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
