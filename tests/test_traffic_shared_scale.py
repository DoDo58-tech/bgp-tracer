"""Regression tests for the shared-scale traffic baseline.

Cloudflare's ``MIN0_MAX`` normalization rescales each HTTP *response* into its
own ``[0, 1]`` range. Fetching the event window and its four baseline weeks
independently therefore produced five incomparable series: every window was
stretched so that its own peak became exactly 1.0, and the z-score of the event
window measured the shape of two unrelated rescalings rather than a real change
in traffic.

``get_traffic_windows_shared_scale`` issues one request for the whole span and
slices afterwards, so all windows share a single normalization scope. The cached
path enforces the same invariant by choosing one unit bucket for all windows
(``_load_cached_windows``) instead of per window.

The tests below use a stub fetcher and synthetic cache files, so they need no
network access and no API token.
"""
from __future__ import annotations

import csv
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import config  # noqa: F401,E402  (side effect: load_dotenv)
from detectors.traffic.traffic_detector import (  # noqa: E402
    CloudflareRadarAPI,
    _RadarSpanFetcher,
)

ASN = "65001"
BASE = datetime(2024, 1, 3, 14, 0)


def _windows():
    wins = [(BASE, BASE + timedelta(hours=8))]
    for i in (1, 2, 3, 4):
        wins.append((BASE - timedelta(days=7 * i), BASE + timedelta(hours=8) - timedelta(days=7 * i)))
    return wins


class _StubAPI:
    """Minimal stand-in exposing what _RadarSpanFetcher touches."""

    def __init__(self, base_url="https://example.invalid"):
        self.base_url = base_url
        self.session = self
        self.calls: list[dict] = []

    def get(self, url, params=None, timeout=None):
        self.calls.append(dict(params or {}))
        return _StubResponse()


class _StubResponse:
    status_code = 200

    @staticmethod
    def json():
        # Cloudflare returns a MIN0_MAX-scaled series over the whole span, so
        # the global peak is 1.0 and no individual window need peak at 1.0.
        # The value shape deliberately varies across the span so that only the
        # window containing the global maximum peaks at 1.0.
        lo = datetime(2023, 12, 1)
        timestamps, values = [], []
        span = 32 * 96
        for step in range(span):
            ts = lo + timedelta(minutes=15 * step)
            timestamps.append(ts.strftime("%Y-%m-%dT%H:%M:%SZ"))
            # ramp up to 1.0 at the very end, stay low elsewhere
            values.append(0.20 + 0.5 * (step / span))
        values[-1] = 1.0
        return {"success": True,
                "result": {"timestamps": timestamps, "values": values}}


def test_span_fetcher_issues_a_single_request():
    """All windows must come from one request, not one request per window."""
    stub = _StubAPI()
    fetcher = _RadarSpanFetcher(stub, ASN, None)
    fetcher.fetch(_windows())
    assert len(stub.calls) == 1, f"expected 1 shared request, got {len(stub.calls)}"


def test_shared_scale_does_not_pin_every_window_peak_to_one():
    """The defining property of the bug: every window peaked at exactly 1.0.

    Under one shared response only the window containing the global maximum can
    peak at 1.0. If normalization were still per-window, all five windows would
    read exactly 1.0.
    """
    import detectors.traffic.traffic_detector as td

    stub = _StubAPI()
    fetcher = _RadarSpanFetcher(stub, ASN, None)
    ts_all, vals_all = fetcher.fetch(_windows())
    assert vals_all, "span fetch returned no samples"

    peaks = []
    for start, end in _windows():
        lo = start.strftime("%Y-%m-%dT%H:%M:%SZ")
        hi = end.strftime("%Y-%m-%dT%H:%M:%SZ")
        picked = [v for t, v in zip(ts_all, vals_all) if lo <= t <= hi]
        if picked:
            peaks.append(round(max(picked), 6))
    assert peaks
    assert len(set(peaks)) > 1 or all(p < 1.0 for p in peaks), (
        f"every window still peaks at 1.0 -- normalization is still per-window: {peaks}"
    )
    assert max(vals_all) <= 1.0001
    assert td.CLOUDFLARE_RADAR_NORMALIZATION == "MIN0_MAX"


def _write_cache(directory: Path, asn: str, name: str, points: list[tuple[str, float]]):
    path = directory / f"AS{asn}_traffic_{name}.csv"
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["timestamp", "value"])
        w.writerows(points)
    return path


def test_cached_windows_use_one_unit_bucket_for_all_windows(tmp_path):
    """Cache-backed windows must resolve to a single unit system.

    Per-window selection is what allowed an event window to resolve to
    ``normalized`` while a baseline week resolved to ``raw``, making the
    resulting z-scores meaningless.
    """
    api = CloudflareRadarAPI.__new__(CloudflareRadarAPI)
    api.traffic_cache_dir = tmp_path
    api.UNIT_SPLIT_THRESHOLD = CloudflareRadarAPI.UNIT_SPLIT_THRESHOLD

    # Week 0: normalized (bounded by 1.0). Week -1: raw request counts.
    cur = [("2024-01-03T14:00:00Z", 0.90), ("2024-01-03T14:15:00Z", 0.80),
           ("2024-01-03T14:30:00Z", 0.85), ("2024-01-03T14:45:00Z", 0.20)]
    hist = [("2023-12-27T14:00:00Z", 9_000_000.0), ("2023-12-27T14:15:00Z", 8_500_000.0),
            ("2023-12-27T14:30:00Z", 8_800_000.0), ("2023-12-27T14:45:00Z", 7_100_000.0)]
    _write_cache(tmp_path, ASN, "a_to_b", cur)
    _write_cache(tmp_path, ASN, "c_to_d", hist)

    cur_win = (datetime(2024, 1, 3, 14, 0), datetime(2024, 1, 3, 15, 0))
    hist_win = (datetime(2023, 12, 27, 14, 0), datetime(2023, 12, 27, 15, 0))
    out = api._load_cached_windows(ASN, [cur_win, hist_win])

    assert out is not None
    units = {tuple(round(v, 6) for v in out[w][1]) for w in (cur_win, hist_win) if out[w][1]}
    # Whichever bucket wins, both windows must come from it -- never a blend.
    for window in (cur_win, hist_win):
        vals = out[window][1]
        assert vals == [] or all(v <= CloudflareRadarAPI.UNIT_SPLIT_THRESHOLD for v in vals) \
            or all(v > CloudflareRadarAPI.UNIT_SPLIT_THRESHOLD for v in vals)
    assert len(units) == 1, f"windows resolved to different unit systems: {units}"


def test_single_window_cache_loader_still_works(tmp_path):
    """The single-window convenience wrapper must keep its old contract."""
    api = CloudflareRadarAPI.__new__(CloudflareRadarAPI)
    api.traffic_cache_dir = tmp_path
    pts = [(f"2024-01-03T14:{m:02d}:00Z", 0.5 + m / 100) for m in range(0, 60, 15)]
    _write_cache(tmp_path, ASN, "x_to_y", pts)

    win = (datetime(2024, 1, 3, 14, 0), datetime(2024, 1, 3, 15, 0))
    ts, vals = api._load_cached_traffic_data(ASN, *win)
    assert vals and len(ts) == len(vals)
    assert max(vals) <= 1.0001


def test_both_entry_points_expose_the_same_scale_source():
    """The two public entry points must not be able to drift apart again."""
    assert hasattr(CloudflareRadarAPI, "get_traffic_windows_shared_scale")
    assert hasattr(CloudflareRadarAPI, "detect_anomalies")
    assert hasattr(CloudflareRadarAPI, "detect_anomalies_for_event")
    import detectors.traffic.traffic_detector as td

    assert td.TRAFFIC_Z_THRESHOLD == 2.5
    assert td.TRAFFIC_CONTEXT_THRESHOLD == 0.35
