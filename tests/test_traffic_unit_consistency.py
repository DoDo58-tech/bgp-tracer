"""Traffic unit-consistency regressions.

BUG (2026-10-05): ``data/traffic/*.csv`` holds two different unit systems in
one directory. Cloudflare's ``normalization=MIN0_MAX`` rescales each response
into [0, 1], while an un-normalized fetch yields raw request counts. Measured
across the 249 cached files: 45 raw vs 204 normalized, and 11 ASNs hold BOTH
kinds at once (AS22773, AS23470, AS52863, AS3223, AS134840, ...).

``_load_cached_traffic_data`` merged every matching file into one dict keyed by
timestamp, so for a window covered by both kinds it returned a single series
that was partly request counts and partly 0-1 floats. Verified at runtime for
AS134840 (1441 normalized + 1021 raw points) and AS23470 (673 + 384). Every
baseline mean/std and every sigma threshold derived from such a series is
meaningless, which is why cross-method accuracy numbers could not be trusted.

The fix classifies each file and refuses to merge across unit systems, keeping
the one with the most samples in the requested window and logging the discard.
This needs no schema change: the ``value`` column keeps its meaning, the
detector consumes floats either way, and the HTML report template never sees
raw samples.
"""
from __future__ import annotations

import csv
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest

from detectors.traffic.traffic_detector import CloudflareRadarAPI

CACHE_DIR = ROOT / "data" / "traffic"


def _api(cache_dir: Path) -> CloudflareRadarAPI:
    api = CloudflareRadarAPI.__new__(CloudflareRadarAPI)
    api.traffic_cache_dir = cache_dir
    api.hasCredentials = False
    return api


def _write_series(path: Path, start: datetime, values, step_minutes: int = 15):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["timestamp", "value"])
        for i, v in enumerate(values):
            ts = start + __import__("datetime").timedelta(minutes=step_minutes * i)
            w.writerow([ts.strftime("%Y-%m-%dT%H:%M:%SZ"), v])


def test_classify_unit_distinguishes_raw_from_normalized():
    api = _api(CACHE_DIR)
    assert api._classify_traffic_unit([0.1, 0.5, 1.0]) == "normalized"
    assert api._classify_traffic_unit([1.9e9, 2.2e9, 1.5e9]) == "raw"
    # A flat normalized series still classifies as normalized.
    assert api._classify_traffic_unit([0.25] * 50) == "normalized"


def test_loader_never_returns_a_mixed_unit_series(tmp_path):
    """Same ASN, same window, one raw file and one normalized file.

    Before the fix these merged into a single series containing both scales.
    """
    _write_series(
        tmp_path / "AS64500_traffic_2025-01-01T00:00:00Z_to_2025-01-01T06:00:00Z.csv",
        datetime(2025, 1, 1, tzinfo=timezone.utc),
        [1.9e9, 1.8e9, 1.95e9] * 8,
    )
    _write_series(
        tmp_path / "AS64500_traffic_2025-01-01T03:00:00Z_to_2025-01-01T09:00:00Z.csv",
        datetime(2025, 1, 1, 3, tzinfo=timezone.utc),
        [0.2, 0.4, 0.9] * 8,
    )
    api = _api(tmp_path)
    got = api._load_cached_traffic_data(
        "64500",
        datetime(2025, 1, 1, tzinfo=timezone.utc),
        datetime(2025, 1, 1, 12, tzinfo=timezone.utc),
    )
    assert got is not None, "expected the raw file to still provide samples"
    _, values = got
    units = {api._classify_traffic_unit([v]) for v in values}
    assert units == {"raw"}, (
        f"loader returned a mixed-unit series ({len(values)} pts, units={units}); "
        "raw counts and MIN0_MAX floats must never share one series"
    )


def test_loader_keeps_single_unit_series_intact(tmp_path):
    """The guard must not damage the common all-raw or all-normalized case."""
    _write_series(
        tmp_path / "AS64501_traffic_2025-01-01T00:00:00Z_to_2025-01-01T06:00:00Z.csv",
        datetime(2025, 1, 1, tzinfo=timezone.utc),
        [1.9e9, 1.8e9, 1.95e9] * 8,
    )
    api = _api(tmp_path)
    got = api._load_cached_traffic_data(
        "64501",
        datetime(2025, 1, 1, tzinfo=timezone.utc),
        datetime(2025, 1, 1, 12, tzinfo=timezone.utc),
    )
    assert got is not None
    _, values = got
    assert len(values) == 24
    assert all(v > 1e8 for v in values), "raw values must be preserved as-is"


def test_event_loader_handles_tz_aware_event_timestamps(tmp_path):
    """The dataset writes event times as "...+00:00" / "...Z".

    The cache column is tz-naive (pd.to_datetime(..., utc=True) then
    .dt.tz_localize(None)). Comparing a tz-aware event bound against a naive
    cache column raises
        TypeError: Invalid comparison between dtype=datetime64[ns] and datetime
    which the HCAF consistency test catches with a bare ``except`` and turns
    into a *synthetic* timeline -- silently replacing real traffic evidence
    with a fixture. That regression moved HCAF review precision from 0.897 to
    0.724 before it was caught.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "_ev", str(ROOT / "scripts" / "eval_hcaf_vs_baselines.py")
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    _write_series(
        tmp_path / "AS64502_traffic_2025-01-01T00:00:00Z_to_2025-01-02T00:00:00Z.csv",
        datetime(2025, 1, 1, tzinfo=timezone.utc),
        [1.9e9, 1.0e9, 1.95e9] * 32,
    )
    for stamp in ("2025-01-01 06:00:00+00:00", "2025-01-01T06:00:00Z"):
        row = {
            "ground_truth_cause_label": "outage",
            "victim_as": "AS64502",
            "start_time_utc": stamp,
            "end_time_utc": stamp,
        }
        try:
            out = mod._load_traffic_csv_for_event(row, tmp_path)
        except TypeError as exc:  # pragma: no cover - the regression itself
            pytest.fail(
                f"tz-aware event timestamp {stamp!r} raised TypeError instead "
                f"of being normalised: {exc}"
            )
        assert isinstance(out, list), "must return a list, never raise"


def test_real_cache_is_free_of_mixed_unit_series():
    """No window over the real cache may yield a mixed-unit series.

    This is the regression that matters for reported accuracy: every ASN and
    every day in the cached span must resolve to exactly one unit.
    """
    if not CACHE_DIR.is_dir():
        pytest.skip("no traffic cache present")

    api = _api(CACHE_DIR)
    files = sorted(CACHE_DIR.glob("AS*_traffic_*_to_*.csv"))
    assert files, "expected cached traffic files"

    # Group files by ASN, then probe each ASN across its own covered span.
    by_asn: dict = {}
    for f in files:
        asn = f.name.split("_")[0][2:]
        by_asn.setdefault(asn, []).append(f)

    mixed = []
    for asn, group in by_asn.items():
        stamps = []
        for f in group:
            try:
                with f.open(newline="", encoding="utf-8") as fh:
                    for row in csv.DictReader(fh):
                        ts = row.get("timestamp") or ""
                        if ts:
                            stamps.append(ts[:10])
            except OSError:
                continue
        if not stamps:
            continue
        start = datetime.fromisoformat(min(stamps)).replace(tzinfo=timezone.utc)
        end = datetime.fromisoformat(max(stamps) + "T23:59:59").replace(tzinfo=timezone.utc)
        got = api._load_cached_traffic_data(asn, start, end)
        if got is None:
            continue
        _, values = got
        units = {api._classify_traffic_unit([v]) for v in values}
        if len(units) > 1:
            mixed.append((asn, len(values)))

    assert not mixed, (
        "these ASNs still return a mixed-unit series from the real cache: "
        f"{mixed}"
    )
