"""Regression tests for the three honesty bugs fixed on 2026-10-05.

P0-1  ReportAgent(bb, enhanced=...) raised TypeError because __init__ only
       accepted `bb`, so the legacy-report fallback could never run.
P0-2  Leak results are capped at max_leaks, but consumers read the capped
       length as if it were the measured count. A run that found 20849 leaks
       was reported as "5000 event(s) detected".
P1    Light/react mode returns success=True placeholders with count 0 and
       score 0.0 for detectors that never ran, so the report claimed a clean
       result for skipped analyses.

All tests are pure-Python; no network and no LLM.
"""

import pytest


# ── P0-1: ReportAgent enhanced kwarg ────────────────────────────────────
class TestReportAgentEnhancedKwarg:
    def test_accepts_enhanced_kwarg(self):
        from agents.report_agent import ReportAgent

        a = ReportAgent(object(), enhanced=True)
        assert a._report_enhanced is True

    def test_defaults_to_false(self):
        from agents.report_agent import ReportAgent

        assert ReportAgent(object())._report_enhanced is False

    def test_legacy_report_call_site_is_valid(self):
        """The exact call workflow_engine makes must not raise."""
        from agents.report_agent import ReportAgent

        class _Ctx:
            enhanced = True

        # Mirrors _run_legacy_report's construction.
        agent = ReportAgent(object(), enhanced=bool(getattr(_Ctx(), "enhanced", False)))
        assert agent._report_enhanced is True


# ── P0-2: leak truncation honesty ────────────────────────────────────────
class TestLeakTruncationIsLabelled:
    def _rows(self, routing_result):
        from agents.report_agent import _collect_routing_security_counts

        return _collect_routing_security_counts(routing_result)

    def _leak_row(self, routing_result):
        for r in self._rows(routing_result):
            if r and r[0] == "Route Leaks":
                return r
        raise AssertionError("no Route Leaks row rendered")

    def test_truncated_count_is_not_presented_as_measurement(self):
        """The real AS8048 numbers: 20849 detected, 5000 returned."""
        row = self._leak_row({
            "leak_count": 5000,
            "leak_count_total": 20849,
            "leak_results_truncated": True,
            "leak_truncation_limit": 5000,
            "route_leaks": [{}] * 5000,
        })
        value, note = row[1], row[2]
        assert value == "≥20849", f"truncated count shown as {value!r}"
        assert "20849" in note
        assert "5000" in note
        assert "not a measurement" in note.lower() or "lower bound" in note.lower()
        # The bare cap must never be presented as the detected total.
        assert "5000 event(s) detected" not in note

    def test_untruncated_count_is_reported_normally(self):
        row = self._leak_row({
            "leak_count": 7,
            "leak_count_total": 7,
            "leak_results_truncated": False,
            "route_leaks": [{}] * 7,
        })
        assert row[1] == "7"
        assert "7 event(s) detected" in row[2]

    def test_zero_leaks_is_not_called_truncated(self):
        row = self._leak_row({
            "leak_count": 0, "leak_count_total": 0,
            "leak_results_truncated": False, "route_leaks": [],
        })
        assert row[1] == "0"
        assert "No route leaks observed" in row[2]

    def test_detector_payload_publishes_truncation_flag(self):
        """The leak detector must expose truncated + the real total."""
        import inspect

        from detectors.leak import leak_detector

        src = inspect.getsource(leak_detector)
        assert '"truncated": truncated' in src
        assert '"truncation_limit"' in src


# ── P1: skipped detectors must not read as clean results ─────────────────
class TestSkippedDetectorsAreNotFalseSuccess:
    def _rows(self, routing_result):
        from agents.report_agent import _collect_routing_security_counts

        return _collect_routing_security_counts(routing_result)

    def _row(self, routing_result, name):
        for r in self._rows(routing_result):
            if r and r[0] == name:
                return r
        raise AssertionError(f"no {name} row rendered")

    def test_skipped_outage_is_not_reported_as_score_zero(self):
        row = self._row({
            "outage_analysis": {
                "success": True, "is_outage_suspected": None,
                "outage_score": None, "skipped": True, "reason": "light_mode",
            },
        }, "Outages")
        assert row[1] == "Skipped", f"skipped outage rendered as {row[1]!r}"
        assert "SKIPPED" in row[2]
        assert "not a measurement" in row[2].lower()
        # Must not claim a clean bill of health.
        assert "No outage suspected" not in row[2]

    def test_real_outage_zero_score_is_still_reported(self):
        """A genuine 0.00 from a detector that RAN must stay as-is."""
        row = self._row({
            "outage_analysis": {
                "success": True, "is_outage_suspected": False,
                "outage_score": 0.0, "skipped": False,
            },
        }, "Outages")
        assert row[1] == "Score 0.00"
        assert "No outage suspected" in row[2]

    def test_skipped_leak_is_not_reported_as_zero_detected(self):
        row = self._row({
            "leak_count": 0, "leak_analysis_skipped": True,
            "leak_analysis": {"skipped": True, "reason": "light_mode"},
            "route_leaks": [],
        }, "Route Leaks")
        assert row[1] == "Skipped", f"skipped leak rendered as {row[1]!r}"
        assert "SKIPPED" in row[2]
        assert "No route leaks observed" not in row[2]

    def test_skipped_hijack_is_not_reported_as_zero_detected(self):
        row = self._row({
            "hijack_analysis_skipped": True,
            "origin_hijacked": [], "forge_hijacked": [],
        }, "Origin Hijacks")
        assert row[1] == "Skipped", f"skipped hijack rendered as {row[1]!r}"
        assert "SKIPPED" in row[2]
        assert "No origin hijacks observed" not in row[2]

    def test_real_zero_hijack_is_still_reported(self):
        """A detector that RAN and found nothing stays a clean 0."""
        row = self._row({
            "hijack_analysis_skipped": False,
            "origin_hijacked": [], "forge_hijacked": [],
        }, "Origin Hijacks")
        assert row[1] == "0"
        assert "No origin hijacks observed" in row[2]

    def test_light_mode_placeholders_use_none_not_zero(self):
        """The placeholder itself must not carry a fake measurement."""
        import inspect

        from agents.impl import routing_impl

        src = inspect.getsource(routing_impl)
        # leak placeholder
        assert '"leak_count": None' in src
        # outage placeholder
        assert '"outage_score": None' in src
        assert '"is_outage_suspected": None' in src
        # and both must be marked skipped
        assert src.count('"skipped": True') >= 2


# ── P1: the 0.00s tracing artefact ──────────────────────────────────────
class TestReportStageRecordsRealElapsed:
    def test_report_saved_stage_is_not_an_empty_block(self):
        """The stage used to wrap `pass`, so elapsed was always 0.00s."""
        import inspect

        from agents import report_agent

        src = inspect.getsource(report_agent)
        assert "_REPORT_GEN_ELAPSED" in src, "real elapsed is not captured"
        assert "elapsed_s_real" in src, "measured elapsed not reported"
