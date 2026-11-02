"""The parquet cache must never claim to hold a window it does not hold.

The archive's ``.gz`` files are **binary** MRT.  The cache builder used
to read them as text, found no line containing ``|A|``, and wrote an
empty frame -- a file that claimed to hold a window and held nothing.
The version check accepted it from then on, so the scan read zero rows
and reported "no routing activity" for a window that was never measured.

Thirty thousand such files accumulated, a quarter of the cache.  The
two properties that must hold are pinned here: a hollow build is never
written, and a source the builder cannot read never replaces a good
cache with an empty one.
"""
from __future__ import annotations

import gzip
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import polars as pl

from data import parquet_cache


def _binary_gz(path: Path):
    """A file that looks like the archive's binary MRT."""
    with gzip.open(path, "wb") as fh:
        fh.write(b"\x00\x01\xe2\x00\x00\x10\x00\x04\x00\x00\x00Z\x00\x00\x1bj")


def test_a_hollow_build_is_not_written(tmp_path, monkeypatch):
    """A source the builder cannot read must leave no cache behind."""
    src = tmp_path / "updates.20200101.0000.gz"
    _binary_gz(src)

    parquet = tmp_path / "updates.20200101.0000.parquet"
    monkeypatch.setattr(parquet_cache, "parquet_path_for", lambda _src: parquet)
    monkeypatch.setattr(parquet_cache, "is_cache_valid", lambda *_a: False)
    monkeypatch.setattr(parquet_cache, "read_gz_into_df", lambda _src: pl.DataFrame())

    result = parquet_cache.ensure_parquet(src)

    assert result is None, "an empty frame must not be published as a cache"
    assert not parquet.exists(), "a hollow parquet was written to disk"
    assert not parquet_cache.meta_path_for(parquet).exists(), \
        "a hollow cache was given a valid metadata stamp"


def test_the_version_check_admits_a_hollow_cache(tmp_path):
    """A hollow file passes the version check -- which is the trap."""
    good = tmp_path / "good.parquet"
    pl.DataFrame({"announce": ["A", "W"], "ts": [None, None]}).write_parquet(good)
    parquet_cache.write_meta(good, good)

    hollow = tmp_path / "hollow.parquet"
    pl.DataFrame({"announce": [], "ts": []}).write_parquet(hollow)
    parquet_cache.write_meta(hollow, hollow)

    # The version check alone cannot tell them apart, which is why the
    # scan consults the row count as well.
    assert parquet_cache.parquet_version_matches(good)
    assert parquet_cache.parquet_version_matches(hollow)

    assert not parquet_cache.parquet_is_hollow(good)
    assert parquet_cache.parquet_is_hollow(hollow)


def test_the_binary_reader_does_not_pretend_to_read_text(tmp_path):
    """The binary reader must decode, not scan for a text marker."""
    src = tmp_path / "updates.20200101.0000.gz"
    _binary_gz(src)

    # The decode helper is what turns binary MRT into the pipe-separated
    # text the frame is read from.  When it is unavailable the reader
    # must decline rather than return an empty frame that looks like a
    # window with no updates.
    monkey = parquet_cache
    original = monkey.decode_gz_to_txt
    monkey.decode_gz_to_txt = None
    try:
        assert monkey.read_gz_into_df(src) is None
    finally:
        monkey.decode_gz_to_txt = original
