"""Repair the hollow parquet files the binary-``.gz`` path produced.

The ``.gz`` archive files are binary MRT.  The cache builder used to read
them as text, found no line containing ``|A|``, and wrote an empty
frame -- a file that claimed to hold a window and held nothing.  The
version check accepted it from then on, so the scan read zero rows and
reported "no routing activity" for a window that was never measured.

This script finds every such file, rebuilds it through ``bgpdump``, and
reports what it could not rebuild.  It is safe to re-run: a file that
already holds rows is left alone.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import polars as pl

from data.parquet_cache import (
    DECODED_DIR,
    PARQUET_DIR,
    UPDATES_ROOT,
    ensure_parquet,
    meta_path_for,
    parquet_is_hollow,
    read_meta,
)


def hollow_paths():
    """Every cached parquet that holds no rows."""
    out = []
    for path in PARQUET_DIR.glob("*.parquet"):
        meta = read_meta(path)
        source = str(meta.get("source", "")) if meta else ""
        if not source.endswith(".gz"):
            continue
        if parquet_is_hollow(path):
            out.append(path)
    return out


def rebuild(path: Path):
    """Rebuild one hollow parquet from its source."""
    meta = read_meta(path)
    source = str(meta.get("source", "")) if meta else ""
    if not source:
        return "no_source"

    src = Path(source)
    if not src.exists():
        stem = path.name[:-len(".parquet")]
        for candidate in (UPDATES_ROOT / f"{stem}.gz",
                          DECODED_DIR / f"{stem}.txt"):
            if candidate.exists() and candidate.stat().st_size > 0:
                src = candidate
                break
        else:
            return "source_missing"

    # The old metadata points at the source that produced the hollow
    # file.  It has to go first, or the builder treats the hollow cache
    # as valid and returns it unchanged.
    meta_path_for(path).unlink(missing_ok=True)
    path.unlink(missing_ok=True)

    try:
        built = ensure_parquet(src)
    except Exception as exc:  # noqa: BLE001
        return f"failed:{type(exc).__name__}"
    if built is None:
        return "build_failed"
    try:
        rows = pl.read_parquet(built, columns=["announce"]).height
    except Exception as exc:  # noqa: BLE001
        return f"unreadable:{type(exc).__name__}"
    if rows == 0:
        return "still_empty"
    return "ok"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args()

    paths = hollow_paths()
    if args.limit:
        paths = paths[: args.limit]
    print(f"hollow parquet files: {len(paths)}", flush=True)

    if not paths:
        return 0

    from concurrent.futures import ProcessPoolExecutor, as_completed

    done = 0
    tally = {}
    started = time.perf_counter()
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(rebuild, path): path for path in paths}
        for fut in as_completed(futures):
            outcome = fut.result()
            tally[outcome] = tally.get(outcome, 0) + 1
            done += 1
            if done % 500 == 0:
                rate = done / (time.perf_counter() - started)
                print(f"  {done}/{len(paths)}  {rate:.1f}/s  {tally}",
                      flush=True)

    print(f"done in {time.perf_counter() - started:.0f}s")
    for outcome, count in sorted(tally.items(), key=lambda kv: -kv[1]):
        print(f"  {outcome:<24} {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
