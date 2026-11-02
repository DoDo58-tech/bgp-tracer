"""Record the row count of every parquet cache in its metadata.

The builder records the count when it writes a cache.  The caches that
predate that do not carry it, so a check that wants to know whether a
cache holds rows has to read the file's data -- which for a hundred
thousand files is hours of reading.  This writes the count once, from
the data that is already there, so the later checks are cheap.
"""
from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path("/data/bgp_tracer")
sys.path.insert(0, str(ROOT))

from data.parquet_cache import (  # noqa: E402
    PARQUET_DIR,
    meta_path_for,
    read_meta,
    write_meta,
)


def record(path: Path):
    """Write the row count into one cache's metadata."""
    meta = read_meta(path)
    if not isinstance(meta, dict):
        return "no_meta"
    if meta.get("rows") is not None:
        return "known"
    if meta.get("schema_version") != 2:
        return "stale_version"
    try:
        import polars as pl

        rows = pl.read_parquet(path, columns=["announce"]).height
    except Exception as exc:  # noqa: BLE001
        return f"unreadable:{type(exc).__name__}"
    source = meta.get("source") or path
    write_meta(path, Path(source), rows=rows)
    return "written"


def main():
    paths = sorted(PARQUET_DIR.glob("*.parquet"))
    print(f"{len(paths)} cache(s)", flush=True)
    counts = {}
    with ThreadPoolExecutor(max_workers=16) as pool:
        for outcome in pool.map(record, paths, chunksize=32):
            counts[outcome] = counts.get(outcome, 0) + 1
    print(counts, flush=True)


if __name__ == "__main__":
    main()
