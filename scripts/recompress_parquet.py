#!/usr/bin/env python3
"""Re-write parquet files with SNAPPY compression instead of ZSTD
for compatibility with older parquet viewers (DuckDB < 0.8, etc.).

Usage:
    python scripts/recompress_parquet.py [--codec snappy] [--in-place]
    python scripts/recompress_parquet.py --codec snappy --in-place
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codec", default="snappy",
                        choices=["snappy", "gzip", "brotli", "lz4", "zstd", "none"],
                        help="Target compression codec (default: snappy)")
    parser.add_argument("--src", default="data/updates_rrc00/parquet",
                        help="Source directory containing *.parquet")
    parser.add_argument("--in-place", action="store_true",
                        help="Overwrite files in place (default: write to *.new.parquet)")
    parser.add_argument("--limit", type=int, default=0, help="Limit N files (debug)")
    args = parser.parse_args()

    src_dir = Path(args.src)
    if not src_dir.is_dir():
        print(f"ERROR: source dir not found: {src_dir}")
        return 2

    codec = args.codec.upper() if args.codec != "none" else "UNCOMPRESSED"
    files = sorted(src_dir.glob("*.parquet"))
    if args.limit:
        files = files[: args.limit]

    print(f"[recompress] files={len(files)} codec={codec} in_place={args.in_place}")
    ok = err = skip = 0
    for i, src in enumerate(files, 1):
        try:
            # Read into Arrow table
            table = pq.read_table(src)
            cur_codec = src.stat().st_size  # placeholder
            # Read original codec from first row group
            md = pq.ParquetFile(src).metadata
            cur = str(md.row_group(0).column(0).compression)
            if cur.upper() == codec:
                skip += 1
                continue
            # Write to temp file then move into place
            if args.in_place:
                tmp = src.with_suffix(".parquet.tmp")
                pq.write_table(table, tmp, compression=codec, use_dictionary=True)
                tmp.replace(src)
            else:
                dst = src.with_name(src.stem + ".snappy.parquet")
                pq.write_table(table, dst, compression=codec, use_dictionary=True)
            ok += 1
            if i % 100 == 0:
                print(f"  [{i}/{len(files)}] ok={ok} err={err} skip={skip}")
        except Exception as exc:
            err += 1
            print(f"  [{i}/{len(files)}] ERROR {src.name}: {type(exc).__name__}: {exc}")
    print(f"[recompress] DONE ok={ok} err={err} skip={skip} total={len(files)}")
    return 0 if err == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
