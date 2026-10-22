"""Regression tests for the 5 critical bugs found in the 2026-10-13 audit.

Each test exercises the synthetic case that exposes the bug, then
asserts the post-fix behaviour. No network, no LLM, no detector runs
end-to-end. The tests are pure-Python unit tests that import the
module under test, call the function, and assert the return value.

Bug list:
- BUG-2026-10-13-A: coordination_utils.load_json referenced undefined
  variable `path` instead of parameter `filepath`.
- BUG-2026-10-13-B: unified_result.Converter.{leak,outage,traffic}_to_unified
  referenced undefined variables leak_result/outage_result/traffic_result.
- BUG-2026-10-13-C: report_agent._verdict_badge referenced undefined
  variable top_cause.
- BUG-2026-10-13-D: report_agent._infer_victim_asns overwrote routing
  parameter with undefined routing_result.
- BUG-2026-10-13-E: report_template.{window_from_artifact_name,
  _normalise_window_hint} referenced undefined variables stem/value.
- BUG-2026-10-13-F: agents.quick_report._kv_table referenced
  undefined rows_html instead of parameter rows.
- BUG-2026-10-13-G: payload_builder crashed on non-integer env vars.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

project_root = Path(__file__).resolve().parents[1]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))


class TestLoadJsonBugFix(unittest.TestCase):
    """BUG-2026-10-13-A: load_json now uses parameter name correctly."""

    def test_load_json_valid_file(self):
        from agents.coordination_utils import load_json
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"a": 1, "b": [2, 3]}, f)
            path = f.name
        try:
            result = load_json(path)
            self.assertEqual(result, {"a": 1, "b": [2, 3]})
        finally:
            os.unlink(path)

    def test_load_json_missing_file(self):
        """Missing file should not raise NameError (was: 'path' is undefined)."""
        from agents.coordination_utils import load_json
        result = load_json("/this/does/not/exist.json")
        self.assertEqual(result, {})

    def test_load_json_malformed_file(self):
        """Malformed JSON should not raise NameError, returns empty dict."""
        from agents.coordination_utils import load_json
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{not valid json")
            path = f.name
        try:
            result = load_json(path)
            self.assertEqual(result, {})
        finally:
            os.unlink(path)


class TestUnifiedResultBugFix(unittest.TestCase):
    """BUG-2026-10-13-B: 3 converter methods now use parameter name correctly."""

    def test_leak_to_unified_empty(self):
        from detectors.unified_result import DetectionResultConverter
        result = DetectionResultConverter.leak_to_unified({"route_leaks": []})
        self.assertEqual(result.anomaly_count, 0)
        self.assertFalse(result.anomalies_detected)

    def test_leak_to_unified_with_items(self):
        from detectors.unified_result import DetectionResultConverter
        payload = {
            "route_leaks": [
                {
                    "timestamp": "2024-01-01T00:00:00Z",
                    "affected_prefixes": ["1.1.1.0/24"],
                    "affected_asns": ["13335"],
                    "event_count": 5,
                    "evidence": {"peer": "AS1234"},
                    "confidence": 0.85,
                }
            ],
            "asn": "13335",
        }
        result = DetectionResultConverter.leak_to_unified(payload)
        self.assertEqual(result.asn, "13335")
        self.assertEqual(result.anomaly_count, 1)
        self.assertEqual(result.anomalies[0].affected_prefixes, ["1.1.1.0/24"])

    def test_outage_to_unified_empty(self):
        from detectors.unified_result import DetectionResultConverter
        result = DetectionResultConverter.outage_to_unified({"is_outage_suspected": False})
        self.assertFalse(result.anomalies_detected)

    def test_outage_to_unified_suspected(self):
        from detectors.unified_result import DetectionResultConverter
        payload = {
            "is_outage_suspected": True,
            "anomaly_count": 10,
            "outage_score": 0.92,
            "asn": "9121",
            "evidence": {"routing_signal": "withdrawal"},
        }
        result = DetectionResultConverter.outage_to_unified(payload)
        self.assertTrue(result.anomalies_detected)
        self.assertEqual(result.asn, "9121")

    def test_traffic_to_unified_empty(self):
        from detectors.unified_result import DetectionResultConverter
        result = DetectionResultConverter.traffic_to_unified({"anomalies": []})
        self.assertEqual(result.anomaly_count, 0)

    def test_traffic_to_unified_with_anomalies(self):
        from detectors.unified_result import DetectionResultConverter
        payload = {
            "anomalies": [
                {
                    "timestamp": "2024-01-01T00:00:00Z",
                    "anomaly_type": "sudden_drop",
                    "duration_seconds": 300,
                    "evidence": {"source": "cf_radar"},
                    "confidence": 0.78,
                }
            ],
            "asn": "16509",
            "data_points": 50,
        }
        result = DetectionResultConverter.traffic_to_unified(payload)
        self.assertEqual(result.asn, "16509")
        self.assertEqual(result.anomaly_count, 1)
        self.assertTrue(result.data_available)

    def test_traffic_to_unified_no_data(self):
        """When data_points=0, data_available should be False."""
        from detectors.unified_result import DetectionResultConverter
        result = DetectionResultConverter.traffic_to_unified(
            {"anomalies": [], "data_points": 0, "success": True}
        )
        self.assertFalse(result.data_available)


class TestVerdictBadgeBugFix(unittest.TestCase):
    """BUG-2026-10-13-C: _verdict_badge uses its parameter now."""

    def test_verdict_badge_with_dict(self):
        from agents.report_agent import _verdict_badge
        result = _verdict_badge({"cause": "route_leak", "confidence": 0.85})
        # Should not raise NameError. Returns HTML string.
        self.assertIn("<span", result)
        self.assertIn("route", result.lower())

    def test_verdict_badge_empty_dict(self):
        from agents.report_agent import _verdict_badge
        result = _verdict_badge({})
        self.assertIn("<span", result)


class TestInferVictimAsnsBugFix(unittest.TestCase):
    """BUG-2026-10-13-D: _infer_victim_asns uses parameter correctly."""

    def test_returns_victims_from_routing_events(self):
        from agents.report_agent import _infer_victim_asns
        routing = {
            "origin_hijacked": [
                {"victim_as": "13335"},
                {"victim_as": "16509"},
            ],
            "forge_hijacked": [
                {"victim_as": "13335"},
            ],
        }
        result = _infer_victim_asns(routing)
        # Should return 2 unique victims
        self.assertEqual(set(result), {"13335", "16509"})

    def test_returns_empty_for_empty(self):
        from agents.report_agent import _infer_victim_asns
        self.assertEqual(_infer_victim_asns({}), [])

    def test_handles_nested_result_key(self):
        """If the input is wrapped under 'result' key, should still work."""
        from agents.report_agent import _infer_victim_asns
        result = _infer_victim_asns({"result": {"origin_hijacked": [{"victim_as": "13335"}]}})
        self.assertEqual(result, ["13335"])


class TestWindowFromArtifactNameBugFix(unittest.TestCase):
    """BUG-2026-10-13-E: window_from_artifact_name and _normalise_window_hint
    use parameter names correctly."""

    def test_window_from_artifact_name_extracts_date(self):
        from agents.report_template import window_from_artifact_name
        window, _end = window_from_artifact_name("event_2024-08-01_08-45")
        self.assertIn("2024-08-01", window)
        self.assertIn("08:45", window)
    def test_window_from_artifact_name_garbage_input(self):
        from agents.report_template import window_from_artifact_name
        window, end = window_from_artifact_name("nope")
        self.assertEqual(window, "")
        self.assertEqual(end, "")

    def test_window_from_artifact_name_empty(self):
        from agents.report_template import window_from_artifact_name
        window, end = window_from_artifact_name("")
        self.assertEqual(window, "")
        self.assertEqual(end, "")


class TestNormaliseWindowHintBugFix(unittest.TestCase):
    """BUG-2026-10-13-E2: _normalise_window_hint uses parameter name correctly."""

    def test_iso_format(self):
        from agents.report_template import _normalise_window_hint
        result = _normalise_window_hint("2024-08-01T08:45:00")
        self.assertTrue(len(result) > 0)

    def test_garbage_returns_empty(self):
        from agents.report_template import _normalise_window_hint
        result = _normalise_window_hint("not a date")
        self.assertEqual(result, "")

    def test_empty_returns_empty(self):
        from agents.report_template import _normalise_window_hint
        result = _normalise_window_hint("")
        self.assertEqual(result, "")

    def test_none_returns_empty(self):
        from agents.report_template import _normalise_window_hint
        result = _normalise_window_hint(None)
        self.assertEqual(result, "")


class TestKvTableBugFix(unittest.TestCase):
    """BUG-2026-10-13-F: _kv_table uses its parameter, not undefined rows_html."""

    def test_kv_table_with_rows(self):
        from agents.quick_report import _kv_table
        result = _kv_table("<tr><td>cell</td></tr>")
        self.assertIn("<table", result)
        self.assertIn("kv-table", result)
        self.assertIn("<tr><td>cell</td></tr>", result)

    def test_kv_table_with_empty_string(self):
        from agents.quick_report import _kv_table
        result = _kv_table("")
        self.assertIn("<table", result)
        self.assertIn("<tbody></tbody>", result)


class TestPayloadBuilderEnvVarBugFix(unittest.TestCase):
    """BUG-2026-10-13-G: payload_builder handles non-integer env vars gracefully."""

    def setUp(self):
        # Clean up any leftover state - thorough
        for k in list(os.environ.keys()):
            if k.startswith("PAYLOAD_BUDGET_"):
                os.environ.pop(k)
        # Remove module from cache
        for mod_name in list(sys.modules.keys()):
            if mod_name.startswith("agents.payload_builder"):
                del sys.modules[mod_name]
        assert os.environ.get("PAYLOAD_BUDGET_REASONING_KB") is None, (
            f"setUp failed to clear env: {os.environ.get('PAYLOAD_BUDGET_REASONING_KB')}"
        )

    def tearDown(self):
        for k in list(os.environ.keys()):
            if k.startswith("PAYLOAD_BUDGET_"):
                os.environ.pop(k)
        for mod_name in list(sys.modules.keys()):
            if mod_name.startswith("agents.payload_builder"):
                del sys.modules[mod_name]

    def test_non_integer_env_var_does_not_crash_import(self):
        # Make sure no leftover env var
        os.environ.pop("PAYLOAD_BUDGET_REASONING_KB", None)
        # Set bad env var
        os.environ["PAYLOAD_BUDGET_REASONING_KB"] = "150kb"  # Non-numeric!
        # Force a complete fresh re-import
        for mod_name in list(sys.modules.keys()):
            if mod_name == "agents.payload_builder" or mod_name == "agents":
                del sys.modules[mod_name]
        # Use direct spec loading to bypass any caching
        import importlib.util
        spec = importlib.util.find_spec("agents.payload_builder")
        mod = importlib.util.module_from_spec(spec)
        sys.modules["agents.payload_builder"] = mod
        spec.loader.exec_module(mod)
        # Module should import without ValueError
        self.assertTrue(hasattr(mod, "_DEFAULT_BUDGETS"))
        # And use the fallback default
        self.assertEqual(
            mod._DEFAULT_BUDGETS["reasoning"],
            150 * 1024,
        )

    def test_integer_env_var_is_respected(self):
        os.environ.pop("PAYLOAD_BUDGET_REASONING_KB", None)
        os.environ["PAYLOAD_BUDGET_REASONING_KB"] = "200"
        for mod_name in list(sys.modules.keys()):
            if mod_name == "agents.payload_builder" or mod_name == "agents":
                del sys.modules[mod_name]
        import importlib.util
        spec = importlib.util.find_spec("agents.payload_builder")
        mod = importlib.util.module_from_spec(spec)
        sys.modules["agents.payload_builder"] = mod
        spec.loader.exec_module(mod)
        self.assertEqual(
            mod._DEFAULT_BUDGETS["reasoning"],
            200 * 1024,
        )


class TestAsyncRetryBugFix(unittest.TestCase):
    """BUG-2026-10-13-H: workflow_engine.async_retry re-raises non-RetryableError."""

    def test_non_retryable_error_propagates(self):
        """A ValueError should be re-raised, not swallowed."""
        import asyncio
        from workflow_engine import async_retry

        @async_retry(max_retries=3)
        async def bad_func():
            raise ValueError("bad input")

        with self.assertRaises(ValueError):
            asyncio.run(bad_func())

    def test_retryable_error_eventually_propagates(self):
        """A RetryableError that exhausts all retries should propagate."""
        import asyncio
        from workflow_engine import async_retry, RetryableError

        @async_retry(max_retries=2, backoff_base=0.01)
        async def always_fails():
            raise RetryableError("transient")

        with self.assertRaises(RetryableError):
            asyncio.run(always_fails())

    def test_successful_call_does_not_retry(self):
        """A function that succeeds on the first try should not be retried."""
        import asyncio
        from workflow_engine import async_retry

        call_count = [0]

        @async_retry(max_retries=3, backoff_base=0.01)
        async def succeeds():
            call_count[0] += 1
            return 42

        result = asyncio.run(succeeds())
        self.assertEqual(result, 42)
        self.assertEqual(call_count[0], 1)


if __name__ == "__main__":
    unittest.main()
