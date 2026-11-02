"""Download and build the parquet cache for windows that are missing it.

The archive scan reads the update files through the parquet cache, and a
window whose parquet is missing has to be decoded before it can be read.
A file that is not in the local archive at all has to be fetched first.

The fetch is the slow part, so the windows are fetched concurrently and
each one is turned into a parquet as soon as it lands.  The parquet is
what the scan reads, so the download is not a separate stage: fetching
and building happen together.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import RIPE_RIS_URL
from data.parquet_cache import (
    DECODED_DIR,
    PARQUET_DIR,
    UPDATES_ROOT,
    ensure_parquet,
    parquet_version_matches,
)

GZ_MIN_BYTES = 50000


def url_for(stamp: str):
    """The archive URL of one five-minute window."""
    year = stamp[:4]
    month = stamp[4:6]
    return f"{RIPE_RIS_URL}{year}.{month}/updates.{stamp}.gz"


def fetch(stamp: str):
    """Download one window's update file."""
    target = UPDATES_ROOT / f"updates.{stamp}.gz"
    if target.exists() and target.stat().st_size >= GZ_MIN_BYTES:
        return target
    url = url_for(stamp)
    try:
        subprocess.check_call(
            ["wget", "-q", "-T", "60", "--tries=2", url, "-O", str(target)],
            timeout=180,
        )
    except Exception:  # noqa: BLE001
        if target.exists():
            target.unlink()
        return None
    if not target.exists() or target.stat().st_size < GZ_MIN_BYTES:
        if target.exists():
            target.unlink()
        return None
    return target


def build(stamp: str):
    """Fetch one window if needed and turn it into a parquet."""
    parquet = PARQUET_DIR / f"updates.{stamp}.parquet"
    if parquet.exists() and parquet_version_matches(parquet):
        return "ready"

    decoded = DECODED_DIR / f"updates.{stamp}.txt"
    if decoded.exists() and decoded.stat().st_size > 0:
        source = decoded
    else:
        source = fetch(stamp)
        if source is None:
            return "download_failed"

    try:
        built = ensure_parquet(source)
    except Exception as exc:  # noqa: BLE001
        return f"build_failed:{type(exc).__name__}"
    if built is None:
        return "build_failed"
    return "ok"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stamps", required=True,
                    help="A file with one YYYYMMDD.HHMM stamp per line.")
    ap.add_argument("--workers", type=int, default=10)
    args = ap.parse_args()

    stamps = [line.strip() for line in
              Path(args.stamps).read_text().splitlines() if line.strip()]
    print(f"windows: {len(stamps)}", flush=True)

    tally = {}
    started = time.perf_counter()
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(build, stamp): stamp for stamp in stamps}
        done = 0
        for fut in as_completed(futures):
            outcome = fut.result()
            tally[outcome] = tally.get(outcome, 0) + 1
            done += 1
            if done % 200 == 0:
                rate = done / (time.perf_counter() - started)
                print(f"  {done}/{len(stamps)}  {rate:.1f}/s  {tally}",
                      flush=True)

    print(f"done in {time.perf_counter() - started:.0f}s")
    for outcome, count in sorted(tally.items(), key=lambda kv: -kv[1]):
        print(f"  {outcome:<24} {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
