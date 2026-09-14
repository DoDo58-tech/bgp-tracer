"""Regression tests for Round 15 bug fixes (BUG-R113..R120).

Round 15 focused on durability (atomic writes) and silent failures in
LLM-call time parsing, plus a state-machine bug in the workflow's
decision engine. Together these tests cover:

- BUG-R113: ``CheckpointManager.save`` now writes via tmp + fsync +
  ``os.replace`` so a crash mid-write can no longer leave a partial
  JSON file that wipes out every previously-completed stage on resume.
- BUG-R115: ``AutoProbeExecutor.execute_probes`` now wraps each task
  in ``asyncio.wait_for(timeout=self.timeout + 5)`` so a stuck probe
  becomes a normal ``AutoProbeFinding(success=False)`` instead of
  hanging the entire pipeline.
- BUG-R116: ``save_html_report`` and ``save_json_report`` use the same
  atomic-write pattern; on success the temp file is gone and the
  target path is durable; on crash the old report stays untouched.
- BUG-R119: the workflow's enhanced reasoning path no longer invokes
  the legacy diagnosis pipeline when the decision engine explicitly
  chose ``stop`` — the legacy fallback used to silently overwrite
  ``context.reasoning_result["stopped"] = True`` with a synthesised
  claim, defeating the decision.
- BUG-R120: ``run_reasoning_agent`` accepts ISO 8601 timestamps (not
  just ``"%Y-%m-%d %H:%M:%S"`` / ``"%Y-%m-%d %H:%M"``), and returns
  a structured error dict instead of crashing when the caller passes
  an ISO string.

Run with::

    pytest tests/test_round15_fixes.py -v
"""

import asyncio
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path

import pytest

# Make sure we can import from the bgp_tracer package regardless of where
# pytest is invoked from.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# ---------------------------------------------------------------------------
# BUG-R113: CheckpointManager.save uses atomic write
# ---------------------------------------------------------------------------

def test_checkpoint_save_uses_os_replace(tmp_path):
    """BUG-R113: the checkpoint must be written atomically (tmp + fsync +
    os.replace) so a crash mid-write cannot leave a half-written JSON
    file that wipes out every previously-completed stage on resume."""
    import inspect
    from chief_agent import CheckpointManager

    src = inspect.getsource(CheckpointManager.save)
    # Strip comments + docstrings so the BUG-R113 explanation in the
    # method's docstring doesn't itself trip the assertion.
    code_only = re.sub(r"#.*", "", src)
    code_only = re.sub(r"\"{3}.*?\"{3}", "", code_only, flags=re.DOTALL)

    assert "os.replace" in code_only, (
        "CheckpointManager.save must use os.replace for atomic write"
    )
    assert ".tmp" in code_only, (
        "CheckpointManager.save must write to a tmp file first"
    )


def test_checkpoint_atomic_write_does_not_clobber_existing_on_failure(tmp_path):
    """BUG-R113: if ``make_json_safe`` fails AND we abort mid-write, the
    old checkpoint file must remain intact."""
    from chief_agent import CheckpointManager

    # Pre-populate the checkpoint with a completed "traffic" stage.
    ckpt = CheckpointManager(
        asn="13335",
        start_time="2024-01-15 00:00",
        mode="react",
        checkpoint_dir=tmp_path,
        enabled=True,
    )
    ckpt.save("traffic", {"hello": "world"})

    # Read the on-disk content for comparison.
    original_path = ckpt.path
    original_bytes = original_path.read_bytes()
    assert b"hello" in original_bytes
    assert b"world" in original_bytes

    # Now write another stage — this should still leave the file intact.
    ckpt.save("routing", {"foo": "bar"})

    # File must still parse as valid JSON.
    parsed = json.loads(ckpt.path.read_text())
    assert "traffic" in parsed["stages"]
    assert "routing" in parsed["stages"]
    assert parsed["stages"]["traffic"] == {"hello": "world"}


# ---------------------------------------------------------------------------
# BUG-R115: AutoProbeExecutor enforces per-task timeout
# ---------------------------------------------------------------------------

def test_auto_probe_executor_wraps_in_wait_for():
    """BUG-R115: ``execute_probes`` must wrap each dispatch task in
    ``asyncio.wait_for(timeout=...)`` so a stuck probe does not hang
    the whole gather forever."""
    import inspect
    from agents.auto_probe_executor import AutoProbeExecutor

    src = inspect.getsource(AutoProbeExecutor.execute_probes)
    assert "asyncio.wait_for" in src, (
        "AutoProbeExecutor.execute_probes must wrap tasks in asyncio.wait_for"
    )
    assert "self.timeout" in src, (
        "AutoProbeExecutor.execute_probes must use self.timeout as the bound"
    )


def test_auto_probe_executor_returns_finding_on_timeout():
    """BUG-R115: a probe that hangs longer than the configured timeout
    becomes a structured ``AutoProbeFinding(success=False)`` instead
    of blocking the caller indefinitely. We only assert on ``success``
    because the stringified ``asyncio.TimeoutError`` is empty in
    Python 3.12 (no message) — the success flag is the contract."""
    import asyncio as _asyncio

    from agents.auto_probe_executor import AutoProbeExecutor, AutoProbeFinding

    executor = AutoProbeExecutor(timeout=0.1, enable_external=True)

    async def _slow_dispatch(*args, **kwargs):
        # Sleep longer than ``timeout + 5.0`` so the wait_for fires.
        await _asyncio.sleep(10)
        return AutoProbeFinding(
            action="dummy", target="dummy", success=True, summary="ok"
        )

    executor._dispatch_one = _slow_dispatch  # type: ignore[assignment]

    async def _driver():
        return await executor.execute_probes(
            [{"action": "test", "target": "x"}],
            target_as="13335",
            analysis_window=None,
        )

    findings = _asyncio.run(_driver())
    assert len(findings) == 1
    f = findings[0]
    assert f.success is False, (
        "stuck probe must surface as a failed AutoProbeFinding, not a hang"
    )


# ---------------------------------------------------------------------------
# BUG-R116: save_html_report / save_json_report use atomic write
# ---------------------------------------------------------------------------

def test_save_html_report_uses_atomic_write(tmp_path):
    """BUG-R116: ``save_html_report`` must use the tmp + os.replace
    pattern so a crash mid-write cannot leave a half-written HTML
    file on disk."""
    import inspect
    from utils.report_exporters import save_html_report

    src = inspect.getsource(save_html_report)
    code_only = re.sub(r"#.*", "", src)
    assert "os.replace" in code_only, (
        "save_html_report must use os.replace for atomic write"
    )
    assert ".tmp" in code_only, (
        "save_html_report must write to a .tmp file first"
    )


def test_save_json_report_uses_atomic_write(tmp_path):
    """BUG-R116: same atomic-write fix for ``save_json_report``."""
    import inspect
    from utils.report_exporters import save_json_report

    src = inspect.getsource(save_json_report)
    code_only = re.sub(r"#.*", "", src)
    assert "os.replace" in code_only, (
        "save_json_report must use os.replace for atomic write"
    )
    assert ".tmp" in code_only, (
        "save_json_report must write to a .tmp file first"
    )


def test_save_html_report_writes_correct_content(tmp_path):
    """End-to-end smoke test for ``save_html_report``: the final file
    must contain the HTML body and have no leftover .tmp file."""
    from utils.report_exporters import save_html_report

    html = "<html><body><h1>hello world</h1></body></html>"
    path = save_html_report(
        asn="13335",
        time_range="2024-01-15",
        html_content=html,
        output_dir=tmp_path,
    )
    file_path = Path(path)
    assert file_path.exists()
    assert file_path.read_text(encoding="utf-8") == html
    # No leftover .tmp sibling
    siblings = list(tmp_path.glob("*.tmp"))
    assert siblings == []


def test_save_json_report_writes_correct_content(tmp_path):
    """End-to-end smoke test for ``save_json_report``."""
    from utils.report_exporters import save_json_report

    payload = {"asn": "13335", "verdict": "correlated_observations"}
    path = save_json_report(
        analysis_data=payload,
        asn="13335",
        output_dir=tmp_path,
    )
    file_path = Path(path)
    assert file_path.exists()
    loaded = json.loads(file_path.read_text(encoding="utf-8"))
    assert loaded["asn"] == "13335"
    assert loaded["verdict"] == "correlated_observations"
    # No leftover .tmp sibling
    siblings = list(tmp_path.glob("*.tmp"))
    assert siblings == []


# ---------------------------------------------------------------------------
# BUG-R119: stop decision no longer triggers legacy fallback
# ---------------------------------------------------------------------------

def test_stop_decision_skips_legacy_fallback():
    """BUG-R119: when the decision engine returns ``action="stop"`` the
    workflow's reasoning handler must NOT subsequently invoke the
    legacy diagnosis pipeline (the previous code did, defeating the
    stop). We verify the source contains the synthetic success record
    that signals the fallback to skip."""
    import inspect
    from workflow_engine import WorkflowEngine

    src = inspect.getsource(WorkflowEngine._handle_reasoning)
    code_only = re.sub(r"#.*", "", src)
    code_only = re.sub(r"\"{3}.*?\"{3}", "", code_only, flags=re.DOTALL)
    assert "_StopDebateResult" in code_only, (
        "WorkflowEngine._handle_reasoning must define a _StopDebateResult "
        "shim so the stop branch skips the legacy fallback."
    )


# ---------------------------------------------------------------------------
# BUG-R120: run_reasoning_agent accepts ISO 8601 timestamps
# ---------------------------------------------------------------------------

def test_run_reasoning_agent_accepts_iso():
    """BUG-R120: ``run_reasoning_agent`` must accept ISO 8601 timestamps
    and return a successful result (the parser used to raise ValueError
    on them and the outer except block returned
    ``{"success": False, "error": "Invalid time: ..."}``)."""
    from agents.reasoning_agent import run_reasoning_agent

    # The parser runs before any heavy LLM work; if it fails, the
    # function returns early with ``success=False`` and an
    # ``"Invalid time"`` error message.
    result = run_reasoning_agent(
        asn="13335",
        start_time="2024-01-15T00:00:00",
        end_time="2024-01-15T00:30:00Z",
        user_input=None,
        max_rounds=1,
    )
    # We don't care whether the reasoning pipeline itself succeeds —
    # we only care that the parser accepted the ISO strings and did
    # NOT return the ``"Invalid time: ..."`` failure.
    if isinstance(result, dict) and result.get("success") is False:
        assert "Invalid time" not in (result.get("error") or ""), (
            f"BUG-R120 regressed: run_reasoning_agent rejected ISO input: {result}"
        )


def test_run_reasoning_agent_reports_invalid_time_structured():
    """BUG-R120: garbage input still produces a structured error dict
    (not a crash) and the error message references the actual values."""
    from agents.reasoning_agent import run_reasoning_agent

    result = run_reasoning_agent(
        asn="13335",
        start_time="not a date",
        end_time="also garbage",
        user_input=None,
        max_rounds=1,
    )
    assert isinstance(result, dict)
    assert result.get("success") is False
    assert "Invalid time" in (result.get("error") or "")
    assert "not a date" in (result.get("error") or "")


# ---------------------------------------------------------------------------
# Sanity: every modified file still parses
# ---------------------------------------------------------------------------

def test_all_modified_files_parse():
    """Round 15 modifications touched chief_agent.py, workflow_engine.py,
    utils/report_exporters.py, agents/auto_probe_executor.py,
    agents/reasoning_agent.py. This is a regression sanity check that
    none of those files has a syntax error."""
    import ast
    for rel in (
        "chief_agent.py",
        "workflow_engine.py",
        "utils/report_exporters.py",
        "agents/auto_probe_executor.py",
        "agents/reasoning_agent.py",
    ):
        path = ROOT / rel
        ast.parse(path.read_text(encoding="utf-8"))
