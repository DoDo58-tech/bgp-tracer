#!/usr/bin/env python3
"""Tests for the forge connection suspicious bug (ROUND-26).

BUG: ``is_suspicious = frequency_ratio <= threshold`` was always True
when ``count == 0`` (0 <= anything). This marked every absent connection
as suspicious, over-counting forge alerts in outage windows.

FIX: require count > 0 before considering the connection suspicious.
"""
import sys
import pytest
from pathlib import Path
import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def test_is_suspicious_requires_count():
    """An absent connection (count==0) must NOT be flagged suspicious."""
    from detectors.hijack.hijack_detector_core import analyze_connection_frequency
    # Build a tiny BGP dataset with no occurrence of the fake connection
    df = pl.DataFrame({
        "as-path": ["123 456 789", "111 222 333", "777 888 999"],
        "timestamp": ["2024-01-01 12:00:00", "2024-01-01 12:01:00", "2024-01-01 12:02:00"],
    })
    df = df.with_columns([
        pl.col("timestamp").str.to_datetime(format="%Y-%m-%d %H:%M:%S", strict=False).cast(pl.Date).cast(pl.String).alias("date"),
    ])
    result = analyze_connection_frequency(
        fake_connection="555|666",  # not in any as-path
        date_str="2024-01-01",
        updates_df=df,
    )
    assert result["count"] == 0
    assert result["is_suspicious"] is False, (
        f"count==0 should not be suspicious, got is_suspicious={result['is_suspicious']}"
    )


def test_is_suspicious_when_count_below_threshold():
    """A rare connection (count < threshold) IS suspicious."""
    from detectors.hijack.hijack_detector_core import analyze_connection_frequency
    # Build a BGP dataset with the fake connection appearing ONCE
    df = pl.DataFrame({
        "as-path": ["123 456 789", "111 222 333", "555 666 777", "888 999 000"],
        "timestamp": ["2024-01-01 12:00:00", "2024-01-01 12:01:00", "2024-01-01 12:02:00", "2024-01-01 12:03:00"],
    })
    df = df.with_columns([
        pl.col("timestamp").str.to_datetime(format="%Y-%m-%d %H:%M:%S", strict=False).cast(pl.Date).cast(pl.String).alias("date"),
    ])
    result = analyze_connection_frequency(
        fake_connection="555|666",
        date_str="2024-01-01",
        updates_df=df,
    )
    assert result["count"] == 1
    # 1/4 = 0.25; the threshold for ASs with low activity is 0.005
    # 0.25 > 0.005, so is_suspicious should be False (the connection is frequent, not rare)
    assert result["is_suspicious"] is False, (
        f"count=1 of 4 should not be suspicious (ratio=0.25), got is_suspicious={result['is_suspicious']}"
    )


def test_is_suspicious_dense_dataset():
    """A large dataset with one rare fake connection should be suspicious."""
    from detectors.hijack.hijack_detector_core import analyze_connection_frequency
    # 1000 normal updates + 1 fake connection
    rows = [
        {"as-path": "123 456 789", "timestamp": f"2024-01-01 12:{i // 60:02d}:{i % 60:02d}"}
        for i in range(1000)
    ]
    rows.append({"as-path": "999 888 555 666", "timestamp": "2024-01-01 12:16:40"})
    df = pl.DataFrame(rows)
    df = df.with_columns([
        pl.col("timestamp").str.to_datetime(format="%Y-%m-%d %H:%M:%S", strict=False).cast(pl.Date).cast(pl.String).alias("date"),
    ])
    result = analyze_connection_frequency(
        fake_connection="555|666",
        date_str="2024-01-01",
        updates_df=df,
    )
    assert result["count"] == 1
    # 1/1001 = 0.001, threshold for low-activity AS is 0.005
    # 0.001 < 0.005 → is_suspicious True (rare connection found)
    assert result["is_suspicious"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
