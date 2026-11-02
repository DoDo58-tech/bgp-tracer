"""Delete the decoded text files that have a parquet beside them.

The decoded ``.txt`` file is an intermediate: the ``.gz`` archive is the
source and the parquet is what the detectors read.  Keeping both costs
eleven terabytes of intermediate text.

A decoded file is removed only when its parquet exists and carries the
current schema version, so nothing that still needs decoding is lost.
The ``.gz`` is never touched, so the window can always be rebuilt.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from data.parquet_cache import (
    DECODED_DIR,
    PARQUET_DIR,
    UPDATES_ROOT,
    parquet_is_hollow,
    parquet_version_matches,
)


def usable_parquet(stem: str):
    """Whether the window's parquet holds real rows.

    The metadata alone is not enough: a hollow file -- one the binary
    ``.gz`` path wrote -- carries a current schema version and would
    pass the version check while holding nothing.  The row count is what
    tells the two apart, so both are checked.
    """
    parquet = PARQUET_DIR / f"{stem}.parquet"
    if not parquet.exists():
        return False
    if not parquet_version_matches(parquet):
        return False
    return not parquet_is_hollow(parquet)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    removed = 0
    freed = 0
    kept = 0
    for path in sorted(DECODED_DIR.glob("updates.*.txt")):
        stem = path.name[:-len(".txt")]
        if not usable_parquet(stem):
            kept += 1
            continue
        size = path.stat().st_size
        if args.dry_run:
            print(f"{path.name}  {size / 1e6:.1f}MB")
        else:
            try:
                path.unlink()
            except OSError:
                kept += 1
                continue
        removed += 1
        freed += size
        if args.limit and removed >= args.limit:
            break

    print(f"removed {removed} decoded files, freed {freed / 1e9:.1f}GB")
    print(f"kept {kept} (no usable parquet yet)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
