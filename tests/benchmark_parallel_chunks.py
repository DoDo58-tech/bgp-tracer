"""Benchmark script: serial vs parallel chunk processing.

Runs `_process_chunk_worker` against 30 synthetic chunks (50K rows each)
and measures:
  1. Wall-clock time on the serial path
  2. Wall-clock time on the parallel path (ThreadPoolExecutor)

Outputs a timing table so we can decide if the refactor is worth shipping.

Run with:
    PYTHONPATH=. python3 tests/benchmark_parallel_chunks.py
"""

from __future__ import annotations

import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import polars as pl

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))


CHUNKS_DIR = Path("/tmp/test_chunks")
PARAMS = {
    "union_target_prefixes": ["1.0.0.0/24", "2.0.0.0/24"],
    "covered_subnet_set": ["1.0.0.0/25", "2.0.0.0/25"],
    "cleaned_as_set": ["65010", "65020", "65030"],
    "cleaned_as_list": ["65010", "65020", "65030"],
    "skip_forge_detection": True,
    "prefix_to_as_subset": {
        "1.0.0.0/24": "65010",
        "2.0.0.0/24": "65020",
        "1.0.0.0/25": "65010",
        "2.0.0.0/25": "65020",
    },
    "as_relationships_data": {},
}


def load_chunks():
    """Load all chunks as list-of-dicts."""
    files = sorted(CHUNKS_DIR.glob("*.parquet"))
    chunks = []
    for f in files:
        df = pl.read_parquet(f)
        keep_cols = [c for c in ["prefix", "as-path", "A/W", "timestamp"] if c in df.columns]
        chunks.append(df.select(keep_cols).to_dicts())
    return chunks


def run_serial(chunks):
    from detectors.hijack.hijack_detector import _process_chunk_worker
    t0 = time.monotonic()
    results = []
    for i, records in enumerate(chunks):
        results.append(_process_chunk_worker((records, PARAMS)))
    elapsed = time.monotonic() - t0
    return elapsed, results


def run_parallel(chunks, n_workers):
    from detectors.hijack.hijack_detector import _process_chunk_worker
    t0 = time.monotonic()
    with ThreadPoolExecutor(max_workers=n_workers) as ex:
        # map() preserves submission order (deterministic output)
        results = list(ex.map(_process_chunk_worker, [(c, PARAMS) for c in chunks]))
    elapsed = time.monotonic() - t0
    return elapsed, results


def main():
    if not CHUNKS_DIR.exists():
        print(f"ERROR: {CHUNKS_DIR} does not exist. Generate test data first.")
        return 1

    print("Loading chunks...")
    chunks = load_chunks()
    print(f"Loaded {len(chunks)} chunks, "
          f"total {sum(len(c) for c in chunks):,} rows\n")

    print("=" * 60)
    print(f"{'Mode':<25} {'Workers':<10} {'Time (s)':<10} {'Speedup':<10}")
    print("=" * 60)

    # Serial baseline
    t_serial, _ = run_serial(chunks)
    print(f"{'serial':<25} {'1':<10} {t_serial:<10.2f} {'1.00x':<10}")

    # Parallel variants
    for nw in [2, 4, 8]:
        t_par, _ = run_parallel(chunks, nw)
        speedup = t_serial / t_par if t_par > 0 else float("inf")
        print(f"{'parallel (ThreadPool)':<25} {nw:<10} {t_par:<10.2f} {speedup:<10.2f}x")

    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
