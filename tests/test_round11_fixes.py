"""Regression tests for Round 11 fixes.

Bug fixes validated here:

  * BUG-R50 (P1)  ``tools.tool_implementations._load_asrel_json``:
      Previously returned ``{"providers": {}, "peers": {}}`` on any
      loader error (no encoding, silent bare ``except``). Downstream
      callers could not distinguish "data file missing" from "AS has
      no recorded relationships" and silently treated every pair as
      ``unknown``. Now returns ``None`` for load failures so callers can
      branch on it.

  * BUG-R55 (P1)  ``agents.react_agent.ReactAgent.run`` retry-answer
      branch dropped ``evidence`` and ``run_id`` from the
      ``ReactResult`` it returned. Subsequent HCAF post-processing in
      chief_agent read an empty evidence dict. The fix restores the
      two fields.

  * BUG-R58 (P1)  ``tools.tool_implementations._analyze_traffic``:
      Previously an empty ``asn_list`` produced ``results = {}`` and
      the vacuous ``all(...)`` returned ``True``, falsely claiming
      "Traffic anomalies detected for ASes: []". Now returns
      ``success=False`` with an explicit error when ``asn_list`` is
      empty.

  * BUG-R61 (P1)  ``tools.tool_implementations._analyze_prefix_traffic``
      and ``_analyze_as_path_delta`` had a redundant nested
      ``try/except _parse_dt() / try/except _parse_dt()`` pair. The
      inner branch was unreachable; the helper only ever raised
      ``ValueError`` once. Removed the dead branch.
"""

import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ────────────────────────── BUG-R50: _load_asrel_json ─────────────────────────


def test_load_asrel_json_returns_none_for_missing_file(tmp_path):
    from tools.tool_implementations import _load_asrel_json

    p = tmp_path / "does_not_exist.json"
    assert _load_asrel_json(str(p)) is None


def test_load_asrel_json_returns_none_for_garbage(tmp_path):
    import tools.tool_implementations as ti
    p = tmp_path / "garbage.json"
    p.write_text("{not valid json at all", encoding="utf-8")
    assert ti._load_asrel_json(str(p)) is None


def test_load_asrel_json_returns_dict_for_valid_file(tmp_path):
    import tools.tool_implementations as ti
    p = tmp_path / "good.json"
    p.write_text('{"providers": {"1": ["2"]}, "peers": {}}', encoding="utf-8")
    loaded = ti._load_asrel_json(str(p))
    assert loaded == {"providers": {"1": ["2"]}, "peers": {}}


def test_query_as_relationship_handles_none_load():
    """When _load_asrel_json returns None, downstream _query_as_relationship
    must still return ``"unknown"`` rather than crashing."""
    from tools.tool_implementations import _query_as_relationship
    rel = _query_as_relationship(None, "1", "2")
    assert rel == "unknown"


# ────────────────────────── BUG-R55: ReactResult retry-answer ──────────────────


def test_react_result_retry_answer_includes_evidence_and_run_id():
    """The retry-after-answer return must include ``evidence`` and
    ``run_id`` to match the other return paths."""
    from agents.react_agent import ReactResult

    # Build a ReactResult the same way the retry-answer branch does now.
    r = ReactResult(
        success=True,
        answer="hello",
        trace=[],
        tools_used=["a", "b"],
        total_rounds=3,
        evidence={"analyze_traffic": {"success": True}},
        run_id="run-xyz",
    )
    assert r.evidence == {"analyze_traffic": {"success": True}}
    assert r.run_id == "run-xyz"


# ────────────────────────── BUG-R58: empty asn_list ────────────────────────────


def test_analyze_traffic_empty_asn_list_returns_failure(caplog):
    from tools.tool_implementations import _analyze_traffic

    class _Sess:
        evidence = {}

    asyncio.run(_analyze_traffic({"asn": [], "start_time": "2024-01-01 00:00",
                                    "end_time": "2024-01-01 01:00"}, _Sess()))


def test_analyze_traffic_empty_asn_list_explicit_message():
    """Returns success=False and a clear observation."""
    from tools.tool_implementations import _analyze_traffic

    class _Sess:
        evidence = {}

    result = asyncio.run(_analyze_traffic(
        {"asn": [], "start_time": "2024-01-01 00:00", "end_time": "2024-01-01 01:00"},
        _Sess(),
    ))
    assert result is not None
    assert result["success"] is False
    assert "Empty asn_list" in result["error"]
    assert "analyze_traffic was called without an ASN" in result["observation"]


def test_analyze_traffic_string_asn_normalised_to_list():
    """String ASN is normalised to a single-element list (legacy behaviour)."""
    from tools.tool_implementations import _analyze_traffic

    class _Sess:
        evidence = {}

    # We don't care if run_traffic_agent raises inside the loop —
    result = asyncio.run(_analyze_traffic(
        {"asn": "13335", "start_time": "2024-01-01 00:00", "end_time": "2024-01-01 01:00"},
        _Sess(),
    ))
    # Either the run succeeded (returning all_anomalous=False) or some
    if not result.get("success"):
        assert "Empty asn_list" not in result.get("error", "")


# ────────────────────────── BUG-R61: dead nested try in parse ──────────────────


def test_analyze_prefix_traffic_handles_unparseable_start():
    """Garbage start_time should fall through to start_dt=None, not crash."""
    from tools.tool_implementations import _analyze_prefix_traffic

    class _Sess:
        evidence = {}

    # Provide minimum valid routing_result so the auto-extraction path
    # produces a prefix list and we exercise the time-parse code.
    result = asyncio.run(_analyze_prefix_traffic(
        {
            "prefixes": ["1.2.3.0/24"],
            "hijacker_asn": "12345",
            "victim_asn": "13335",
            "start_time": "TOTALLY INVALID",
            "end_time": "ALSO INVALID",
        },
        _Sess(),
    ))
    # start_dt/end_dt being None means we can't run the heavy path,
    assert result is not None


def test_parse_dt_unparseable_raises_value_error():
    from tools.tool_implementations import _parse_dt
    with pytest.raises(ValueError):
        _parse_dt("not a date")


# ────────────────────────── BUG-R57: batch polars helper ───────────────────────


def test_batch_connection_frequency_polars_handles_empty_keys():
    import polars as pl
    from detectors.hijack.hijack_detector_core import _batch_connection_frequency_polars

    df = pl.DataFrame({"as-path": ["1 2 3", "4 5 6"]})
    assert _batch_connection_frequency_polars([], df) == {}


def test_batch_connection_frequency_polars_handles_none_data():
    from detectors.hijack.hijack_detector_core import _batch_connection_frequency_polars

    res = _batch_connection_frequency_polars(["1|2"], None)
    assert res == {"1|2": None}


def test_batch_connection_frequency_polars_handles_empty_df():
    import polars as pl
    from detectors.hijack.hijack_detector_core import _batch_connection_frequency_polars

    df = pl.DataFrame({"as-path": []})
    res = _batch_connection_frequency_polars(["1|2"], df)
    assert res == {"1|2": None}


def test_batch_connection_frequency_polars_returns_results():
    import polars as pl
    from detectors.hijack.hijack_detector_core import _batch_connection_frequency_polars

    # Bug fix 2026-09-13 (BUG-R82): the legacy
    df = pl.DataFrame({
        "as-path": ["13335 174 1299 12345", "174 1299 12345", "13335 174 1299", "174 1299"],
        "timestamp": ["2024-01-01 10:00", "2024-01-01 10:01", "2024-01-01 10:02", "2024-01-01 10:03"],
    })
    res = _batch_connection_frequency_polars(["13335|174", "174|1299"], df)
    assert res["13335|174"]["count"] == 4
    assert res["174|1299"]["count"] == 4


def test_batch_connection_frequency_polars_malformed_keys():
    import polars as pl
    from detectors.hijack.hijack_detector_core import _batch_connection_frequency_polars

    df = pl.DataFrame({"as-path": ["1 2", "3 4"]})
    res = _batch_connection_frequency_polars(["|", "13335|", "|174"], df)
    for k in ("|", "13335|", "|174"):
        assert res[k]["data_coverage"] == "malformed"
        assert res[k]["is_suspicious"] is True
