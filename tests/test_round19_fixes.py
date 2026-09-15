"""
Regression tests for Round 19 bug fixes - locking in Bug 1 and Bug 2.

The original bugs were documented in comprehensive_evaluation_report.md:

BUG-R133 (Bug 1):
    agents/enhanced/multi_report.py had a SyntaxError when the closing
    triple-quote of a multiline prompt template was followed immediately
    by the next statement on the same line.  That made the entire
    agents.enhanced package un-importable, blocking all enhanced modes.

BUG-R134 (Bug 2):
    ConfidenceCalibratorAgent.calibrate() in multi_report.py returned
    calibrated_text that was actually a copy of its own prompt (LLM echo),
    so users saw only the prompt text instead of the analysis.
"""
from __future__ import annotations

import importlib
import json
import re
import sys
import asyncio
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ===========================================================================
# Helpers
# ===========================================================================

def _patch_llm_json_call(monkeypatch, payload_obj):
    """Patch llm_json_call in agents.enhanced.multi_report to return payload_obj."""
    import agents.enhanced.multi_report as mr
    monkeypatch.setattr(mr, "llm_json_call", lambda *a, **kw: payload_obj)


# ===========================================================================
# BUG 1 / R133: agents/enhanced/multi_report.py must import without SyntaxError
# ===========================================================================

def test_enhanced_module_imports_clean():
    """agents.enhanced.multi_report must import without SyntaxError."""
    if "agents.enhanced.multi_report" in sys.modules:
        importlib.reload(sys.modules["agents.enhanced.multi_report"])
    else:
        import agents.enhanced.multi_report  # noqa: F401
    assert "agents.enhanced.multi_report" in sys.modules


def test_confidence_calibrator_class_is_exposed():
    """ConfidenceCalibratorAgent must be reachable from the module."""
    from agents.enhanced.multi_report import ConfidenceCalibratorAgent
    assert ConfidenceCalibratorAgent is not None


def test_calibrate_is_coroutine_function():
    """calibrate must be async so it can be awaited by the coordinator."""
    import inspect
    from agents.enhanced.multi_report import ConfidenceCalibratorAgent
    assert inspect.iscoroutinefunction(ConfidenceCalibratorAgent.calibrate), (
        "calibrate() must be a coroutine - the enhanced report pipeline "
        "depends on this."
    )


def test_user_prompt_closure_has_newline_before_next_statement():
    """Regression guard for Bug 1.

    The reported regression was: a prompt template that closes with
    close-brace close-brace triple-quote immediately followed (no newline)
    by parsed = llm_json_call( on the same line, producing a SyntaxError.

    Find the calibration user prompt specifically and confirm that the
    closing triple-quote is followed by a newline before the parsed
    assignment.
    """
    p = PROJECT_ROOT / "agents" / "enhanced" / "multi_report.py"
    src = p.read_text(encoding="utf-8")

    # Match: calibration task intro -> triple-quote -> parsed assignment.
    # Require at least one newline between closing triple-quote and parsed.
    calib_pat = re.compile(
        r'Calibrate the confidence language\.'
        r'[\s\S]*?"""'
        r'\s*\n\s*\n?\s*'  # at least one newline, optional blank line
        r'parsed\s*=\s*llm_json_call\(',
    )
    m = calib_pat.search(src)
    assert m is not None, (
        "Bug 1 regression detected (or prompt template refactored): the "
        "calibration user prompt should close with a newline before "
        "parsed = llm_json_call( starts."
    )


# ===========================================================================
# BUG 2 / R134: Prompt-echo detection in ConfidenceCalibratorAgent.calibrate
# ===========================================================================

def test_prompt_echo_markers_constant_includes_all_required_phrases():
    """The echo detection must check for the five known prompt-echo phrases."""
    from agents.enhanced.multi_report import ConfidenceCalibratorAgent
    import inspect

    src = inspect.getsource(ConfidenceCalibratorAgent.calibrate)
    required = [
        "calibrate the confidence language",
        "return json:",
        "calibrated_text",
        "calibration_log",
        "original_phrase",
    ]
    missing = [m for m in required if m not in src]
    assert not missing, (
        f"calibrate() must check for these prompt-echo markers: missing {missing}"
    )


def test_prompt_echo_length_threshold_is_200():
    """The echo-detection threshold must be 200 chars (length < 200 = suspicious)."""
    from agents.enhanced.multi_report import ConfidenceCalibratorAgent
    import inspect

    src = inspect.getsource(ConfidenceCalibratorAgent.calibrate)
    has_thresh = ("len(calibrated) < 200" in src) or ("len(calibrated)<200" in src)
    assert has_thresh, (
        "calibrate() must reject echoed prompts shorter than 200 chars."
    )


def test_calibrate_skips_html_input_directly():
    """calibrate() returns early (no LLM call) for HTML input."""
    from agents.enhanced.multi_report import ConfidenceCalibratorAgent

    agent = ConfidenceCalibratorAgent(llm=None)
    html_report = "<html><body><p>Analysis here</p></body></html>"
    # No LLM needed - this path is already exercised by the HTML-detection guard.
    # The HTML guard is the first line of calibrate() so we test it explicitly.
    calibrated, log = asyncio.run(agent.calibrate(
        report_text=html_report,
        correlation_level="L1",
        confidence=0.85,
    ))
    # HTML is returned as-is with a "skipped" log entry.
    assert calibrated == html_report
    assert len(log) == 1
    assert log[0].get("issue") == "skipped"


def test_prompt_echo_detected_and_falls_back(monkeypatch):
    """Short payload (< 200) that contains a known marker must trigger fallback.

    Use non-HTML input so we bypass the HTML guard and reach llm_json_call.
    """
    from agents.enhanced.multi_report import ConfidenceCalibratorAgent

    # This is the actual echo pattern that AS7420 exhibited.
    echo_text = (
        "Calibrate the confidence language. Return JSON: "
        "{ calibrated_text, calibration_log, original_phrase ... }"
    )
    assert len(echo_text) < 200, "test fixture broke - echo payload too long"

    payload_obj = json.loads(json.dumps({
        "calibrated_text": echo_text,
        "calibration_log": [],
    }))
    _patch_llm_json_call(monkeypatch, payload_obj)

    agent = ConfidenceCalibratorAgent(llm=None)
    # Use plain text (not HTML) to exercise the calibration path.
    original_report = (
        "This is a real analysis report with many paragraphs of actual "
        "content. It discusses the BGP routing anomaly that was detected, "
        "the traffic drop observed, and the correlation between them. "
        "This paragraph has over 200 characters to confirm we bypass "
        "the echo guard."
    )
    calibrated, log = asyncio.run(agent.calibrate(
        report_text=original_report,
        correlation_level="L1",
        confidence=0.85,
    ))

    assert calibrated == original_report, (
        f"Prompt echo was not detected and fallback was not applied; "
        f"got: {calibrated[:200]!r}"
    )
    assert log == [], (
        f"calibration_log must be cleared when fallback fires; got log={log!r}"
    )


def test_non_echo_short_response_is_preserved(monkeypatch):
    """Short payload (< 200 chars) WITHOUT markers must pass through untouched.

    Use non-HTML input so we reach llm_json_call.
    """
    from agents.enhanced.multi_report import ConfidenceCalibratorAgent

    short_valid = "Likely."
    payload_obj = json.loads(json.dumps({
        "calibrated_text": short_valid, "calibration_log": [],
    }))
    _patch_llm_json_call(monkeypatch, payload_obj)

    agent = ConfidenceCalibratorAgent(llm=None)
    # Plain text - no HTML guard interference.
    original_report = (
        "The routing anomaly is clearly documented with strong evidence."
    )
    calibrated, _ = asyncio.run(agent.calibrate(
        report_text=original_report,
        correlation_level="L1",
        confidence=0.9,
    ))
    assert calibrated == short_valid, (
        f"Short but valid calibrated text should pass through; got {calibrated!r}"
    )


def test_long_text_with_marker_is_not_reclassified(monkeypatch):
    """Long payloads (> 200 chars) with markers must NOT be reclassified as echo.

    Use non-HTML input so we reach llm_json_call.
    """
    from agents.enhanced.multi_report import ConfidenceCalibratorAgent

    long_text = (
        ("Long legitimate content. " * 30) + " calibration_log appendix reference."
    )
    assert len(long_text) >= 200
    payload_obj = json.loads(json.dumps({
        "calibrated_text": long_text, "calibration_log": [],
    }))
    _patch_llm_json_call(monkeypatch, payload_obj)

    agent = ConfidenceCalibratorAgent(llm=None)
    calibrated, _ = asyncio.run(agent.calibrate(
        report_text="Short original report text.",  # plain text
        correlation_level="L1",
        confidence=0.85,
    ))
    assert calibrated == long_text, (
        f"Long content mentioning a marker should NOT be reclassified as echo; "
        f"got first 100 chars: {calibrated[:100]!r}"
    )


def test_empty_or_missing_calibrated_text_uses_original(monkeypatch):
    """Defensive fallback: empty/None/missing calibrated_text -> original report.

    Uses non-HTML input to exercise the llm_json_call path (not the HTML guard).
    """
    from agents.enhanced.multi_report import ConfidenceCalibratorAgent

    original_report = (
        "The BGP routing event was likely caused by a configuration error."
    )
    cases = [
        {"calibrated_text": "", "calibration_log": []},
        {"calibrated_text": None, "calibration_log": []},
        {"calibration_log": []},  # missing key entirely
    ]
    for case in cases:
        payload_obj = json.loads(json.dumps(case))
        import agents.enhanced.multi_report as mr
        mr.llm_json_call = lambda *a, **kw: payload_obj
        agent = ConfidenceCalibratorAgent(llm=None)
        calibrated, _ = asyncio.run(agent.calibrate(
            report_text=original_report,
            correlation_level="L1",
            confidence=0.5,
        ))
        assert calibrated == original_report, (
            f"payload={case!r} should fall back to original; got {calibrated!r}"
        )
        del mr.llm_json_call
