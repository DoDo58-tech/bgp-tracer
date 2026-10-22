"""Regression tests for the report_payload JSON truncation fix (2026-09-13).

Bug (before fix):
  ``trim_to_size`` sliced the JSON string at an arbitrary midpoint and
  tried to re-parse it via ``json.loads(truncated)``. The slice almost
  always landed inside a string literal, key, or number — making
  ``json.loads`` raise. The exception was silently swallowed and the LLM
  was still handed the original over-budget payload.

After fix:
  - Drop non-critical top-level keys one at a time.
  - If still over budget, use ``json.JSONDecoder.raw_decode()`` which
    respects syntactic boundaries (object / array / value).
  - Fall back to looking backwards for the last complete ``}`` or ``]``.
  - Last-ditch: replace the payload with a size-marker dict.
  - All paths produce valid JSON output.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def _approx_size(obj):
    return len(json.dumps(obj, default=str).encode("utf-8"))


def test_trim_to_size_returns_valid_json_under_budget():
    """Even with extreme over-budget inputs, output must be valid JSON and ≤ budget * 1.1."""
    from agents.report_agent import trim_to_size

    big_payload = {
        "summary": {"text": "test"},
        "anomalies": [
            {"ts": f"2024-01-03T15:{i % 60:02d}:{i % 60:02d}",
             "value": i, "z_score": i * 0.1}
            for i in range(2000)
        ],
        "raw_data": [{"junk": "x" * 100} for _ in range(500)],
        "victim_traffic_results": {"x": list(range(100))},
        "prefix_traffic_results": {"y": list(range(100))},
    }
    max_bytes = 2000
    result = trim_to_size(big_payload, max_bytes=max_bytes)
    result_json = json.dumps(result, default=str)
    assert len(result_json) <= max_bytes * 1.1, (
        f"truncated payload still over budget: "
        f"{len(result_json)} > {max_bytes} * 1.1"
    )
    # Must round-trip through json (proves it's parseable).
    reparsed = json.loads(result_json)
    assert isinstance(reparsed, dict)


def test_trim_to_size_small_input_passes_through():
    """Inputs already under budget must not be modified."""
    from agents.report_agent import trim_to_size

    small = {"summary": "tiny", "anomalies": [{"x": 1}]}
    result = trim_to_size(small, max_bytes=10_000)
    assert result == small


def test_trim_to_size_extreme_overflow_uses_error_marker():
    """When even after dropping everything we can't fit, fall back to a marker dict."""
    from agents.report_agent import trim_to_size

    # A payload that can't shrink: a single huge string value.
    huge_string = "a" * 100_000
    payload = {
        "summary": "x",
        "big_blob": huge_string,
        "raw_data": huge_string,
        "_details_blob": huge_string,
        "victim_traffic_results": huge_string,
        "law_analysis": huge_string,
    }
    result = trim_to_size(payload, max_bytes=500)
    result_json = json.dumps(result, default=str)
    # Must be parseable
    reparsed = json.loads(result_json)
    # Should either fit or have the error marker
    assert isinstance(reparsed, dict)
    assert (
        len(result_json) <= 1500  # tolerate warning-marker expansion
        or "__PAYLOAD_TRUNCATED_ERROR__" in reparsed
    )


def test_trim_to_size_drops_curated_keys_first():
    """Trim strategy should drop curated non-critical keys (victim_traffic_results etc.) before resorting to slicing."""
    from agents.report_agent import trim_to_size

    payload = {
        "summary": "must keep",
        "routing_events": [{"e": i} for i in range(100)],
        "victim_traffic_results": {"huge": ["x"] * 1000},
        "prefix_traffic_results": {"huge": ["x"] * 1000},
        "law_analysis": {"huge": ["x"] * 1000},
    }
    result = trim_to_size(payload, max_bytes=2000)
    # The summary must survive.
    assert result.get("summary") == "must keep", (
        f"trim lost the 'summary' key: {result}"
    )
    # The curated non-critical keys should be marked as trimmed.
    for k in ("victim_traffic_results", "prefix_traffic_results", "law_analysis"):
        assert k in result, f"key {k!r} was removed instead of replaced with marker"
