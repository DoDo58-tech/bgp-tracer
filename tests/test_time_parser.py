"""Regression tests for the multi-format time parser in traffic_detector.

Bug fix 2026-09-15: previously ``_parse_iso`` only accepted the two
formats ``"%Y-%m-%d %H:%M:%S"`` and ``"%Y-%m-%d %H:%M"``. ISO 8601
formats with ``T`` separator, ``Z`` suffix, microseconds, and offsets
all raised ``ValueError`` — the ReAct loop would then call the tool
repeatedly with the same bad format and burn both tokens and time.
"""
import sys
sys.path.insert(0, '/data/bgp_tracer')

from datetime import datetime
from detectors.traffic.traffic_detector import _parse_iso, _parse_iso_utc


def test_parse_iso_canonical_with_seconds():
    assert _parse_iso("2024-07-31 08:30:00") == datetime(2024, 7, 31, 8, 30)


def test_parse_iso_canonical_without_seconds():
    assert _parse_iso("2024-07-31 08:30") == datetime(2024, 7, 31, 8, 30)


def test_parse_iso_iso_t_with_seconds():
    # The format the LLM was emitting that broke before the fix.
    assert _parse_iso("2024-07-31T08:30:00") == datetime(2024, 7, 31, 8, 30)


def test_parse_iso_iso_z_suffix():
    result = _parse_iso("2024-07-31T08:30:00Z")
    assert result.year == 2024 and result.month == 7 and result.day == 31
    assert result.hour == 8 and result.minute == 30


def test_parse_iso_with_microseconds():
    result = _parse_iso("2024-07-31T08:30:00.123")
    assert result.microsecond == 123000


def test_parse_iso_with_offset():
    result = _parse_iso("2024-07-31T08:30:00+00:00")
    assert result.hour == 8 and result.minute == 30


def test_parse_iso_with_slash_separator():
    assert _parse_iso("2024/07/31 08:30:00") == datetime(2024, 7, 31, 8, 30)


def test_parse_iso_strips_whitespace():
    assert _parse_iso("  2024-07-31 08:30  ") == datetime(2024, 7, 31, 8, 30)


def test_parse_iso_empty_returns_clear_error():
    try:
        _parse_iso("")
    except ValueError as exc:
        assert "empty" in str(exc).lower()
    else:
        raise AssertionError("empty input should raise")


def test_parse_iso_garbage_raises_clear_error():
    try:
        _parse_iso("not-a-date")
    except ValueError as exc:
        assert "not-a-date" in str(exc)
    else:
        raise AssertionError("garbage input should raise")


def test_parse_iso_utc_accepts_iso_z():
    result = _parse_iso_utc("2024-07-31T08:30:00Z")
    assert result is not None
    assert result.hour == 8


def test_parse_iso_utc_accepts_space_format():
    # The original format ``"%Y-%m-%d %H:%M:%S"`` must still work.
    result = _parse_iso_utc("2024-07-31 08:30:00")
    assert result is not None
    assert result.hour == 8


def test_parse_iso_utc_returns_none_for_garbage():
    assert _parse_iso_utc("not-a-date") is None


def test_parse_iso_utc_returns_none_for_empty():
    assert _parse_iso_utc("") is None
    assert _parse_iso_utc(None) is None


if __name__ == "__main__":
    test_parse_iso_canonical_with_seconds()
    test_parse_iso_canonical_without_seconds()
    test_parse_iso_iso_t_with_seconds()
    test_parse_iso_iso_z_suffix()
    test_parse_iso_with_microseconds()
    test_parse_iso_with_offset()
    test_parse_iso_with_slash_separator()
    test_parse_iso_strips_whitespace()
    test_parse_iso_empty_returns_clear_error()
    test_parse_iso_garbage_raises_clear_error()
    test_parse_iso_utc_accepts_iso_z()
    test_parse_iso_utc_accepts_space_format()
    test_parse_iso_utc_returns_none_for_garbage()
    test_parse_iso_utc_returns_none_for_empty()
    print("All 14 time-parser regression tests passed")
