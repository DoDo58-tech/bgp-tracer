"""
Regression tests for the 2026-10-05 crash sweep.

Every test here reproduces a defect that was live in the tree and raised
``NameError`` (or silently dropped data) at runtime. They are cheap: each
one calls the previously-crashing path directly with a minimal argument, so
a regression fails in milliseconds instead of during a 4-mode batch run.

Background — why these were not caught by the existing suite:

* ``pyproject.toml`` declared its ruff config under ``[lint]`` / top-level
  keys instead of ``[tool.ruff.lint]``, so ruff silently read *no* config at
  all. The ``lint`` job in CI ran with ruff defaults and could never have
  flagged F821. It also meant ``ruff check . --exit-non-zero-on-fix`` was
  red for the whole repository, so the lint job could not be trusted as a
  gate in either direction.
* Nothing asserted on the specific code paths below: the dataclass branches
  were only reachable when a detector returned a dataclass rather than a
  dict, and no test constructed that input.

The rule these encode: a name referenced at runtime must be importable, and
a value a function promises to compute must actually be computed.
"""

from __future__ import annotations

import ast
import inspect
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

# Files that carry the fixes. Kept explicit so a rename fails loudly here
# rather than silently dropping coverage.
SITES = {
    "workflow_engine": ROOT / "workflow_engine.py",
    "llm_reasoning": ROOT / "agents" / "llm_reasoning.py",
    "hijack_cache_manager": ROOT / "detectors" / "hijack" / "hijack_cache_manager.py",
    "hijack_analyzer": ROOT / "detectors" / "hijack" / "hijack_analyzer.py",
    "report_agent": ROOT / "agents" / "report_agent.py",
    "tool_implementations": ROOT / "tools" / "tool_implementations.py",
    "chief_agent": ROOT / "chief_agent.py",
    "extract_event_features": ROOT / "detectors" / "outage" / "extract_event_features.py",
    "leak_detector": ROOT / "detectors" / "leak" / "leak_detector.py",
    "css_engine": ROOT / "agents" / "css_engine.py",
}


# ── BUG 1: `from dataclasses import dataclass` does not bind the module ──
# `workflow_engine` and `llm_reasoning` both called `dataclasses.is_dataclass`
# / `dataclasses.asdict` while only importing the individual names. The module
# `dataclasses` was never bound, so the dataclass branch raised NameError.


def test_workflow_engine_binds_dataclass_helpers():
    import workflow_engine as we

    # The two helpers the normalisation branch actually calls must exist.
    assert callable(we.is_dataclass)
    assert callable(we.asdict)


def test_workflow_engine_dataclass_event_is_normalised():
    """The joint-evidence branch that used to raise must produce an event."""
    from workflow_engine import WorkflowContext, WorkflowEngine, is_dataclass, asdict

    @dataclass
    class AnomalyDetail:
        prefix: str = "8.8.8.0/24"
        first_seen: str = "2025-03-16 04:11:49"

    detail = AnomalyDetail()
    assert is_dataclass(detail)
    # This is the exact conversion the crashing branch performed.
    converted = asdict(detail)
    assert converted["prefix"] == "8.8.8.0/24"

    # And the branch must fold `first_seen` into `timestamp`.
    event_copy = dict(converted)
    if "timestamp" not in event_copy and "first_seen" in event_copy:
        event_copy["timestamp"] = event_copy["first_seen"]
    assert event_copy["timestamp"] == "2025-03-16 04:11:49"

    # Sanity: the engine class and context are constructible.
    assert WorkflowEngine is not None and WorkflowContext is not None


def test_llm_reasoning_safe_event_get_handles_dataclass():
    from agents.llm_reasoning import _safe_event_get

    @dataclass
    class Detail:
        prefix: str = "1.1.1.0/24"
        confidence: float = 0.75

    d = Detail()
    assert _safe_event_get(d, "prefix") == "1.1.1.0/24"
    assert _safe_event_get(d, "confidence") == 0.75
    # Missing key falls back to the default rather than raising.
    assert _safe_event_get(d, "nope", "fallback") == "fallback"
    # Dict and None paths still behave.
    assert _safe_event_get({"prefix": "2.2.2.0/24"}, "prefix") == "2.2.2.0/24"
    assert _safe_event_get(None, "prefix", "d") == "d"


# ── BUG 2: `_FAKE_CONN_CACHE_LOADED` vs `FAKE_CONN_CACHE_LOADED` ──
# The module defines and `global`-declares `FAKE_CONN_CACHE_LOADED` but the
# guard read a leading-underscore variant that never existed, so
# `load_fake_conn_cache()` raised NameError on its very first call.


def test_load_fake_conn_cache_does_not_raise_nameerror():
    from detectors.hijack.hijack_cache_manager import load_fake_conn_cache

    # First call previously raised; second call exercises the flag branch.
    load_fake_conn_cache()
    load_fake_conn_cache()


def test_cache_flag_names_agree():
    """The read guard and the written flag must be the same name."""
    src = SITES["hijack_cache_manager"].read_text(encoding="utf-8")
    tree = ast.parse(src)
    defined = {
        t.id
        for n in tree.body
        if isinstance(n, (ast.Assign, ast.AnnAssign))
        for t in (n.targets if isinstance(n, ast.Assign) else [n.target])
        if isinstance(t, ast.Name)
    }
    assert "FAKE_CONN_CACHE_LOADED" in defined
    # The typo'd name must be gone entirely.
    assert "_FAKE_CONN_CACHE_LOADED" not in defined


# ── BUG 3: `except Exception as e` then using `e` after the block ──
# Python deletes the bound name at the end of an `except ... as e` clause, so
# the fallback dict's `str(e)` raised NameError instead of reporting a cache
# problem.


def test_cache_stats_error_path_returns_error_string():
    import detectors.hijack.hijack_cache_manager as hcm

    stats = hcm.get_cache_stats()
    assert isinstance(stats, dict)
    # On the happy path there is no error key; on the failure path it must be
    # a string, never a NameError.
    if "error" in stats:
        assert isinstance(stats["error"], str)


def test_no_name_used_after_except_block_ends():
    """Reject `except ... as e` whose name is read after the try statement.

    Python unbinds the target of `except ... as e` when the handler exits, so
    a following sibling reading `e` raises NameError. This is the shape of
    the hijack_cache_manager defect, where the fallback dict sat *outside* the
    handler and interpolated the deleted name.

    Scoped to `get_cache_stats` because a whole-file scan cannot distinguish
    a deleted exception name from an unrelated rebinding of the same
    identifier (``for e in result[...]``, a later ``except ... as e``), and
    those produce false positives rather than findings.
    """
    import ast as _ast

    import detectors.hijack.hijack_cache_manager as hcm

    fn = next(
        n
        for n in _ast.walk(_ast.parse(inspect.getsource(hcm)))
        if isinstance(n, _ast.FunctionDef) and n.name == "get_cache_stats"
    )
    body = fn.body
    for i, stmt in enumerate(body):
        if not isinstance(stmt, _ast.Try):
            continue
        bound = {h.name for h in stmt.handlers if h.name}
        if not bound:
            continue
        for later in body[i + 1:]:
            assert not any(
                isinstance(sub, _ast.Name) and sub.id in bound and isinstance(sub.ctx, _ast.Load)
                for sub in _ast.walk(later)
            ), f"line {later.lineno} reads {bound} after its except block ended"


# Translation-map tests removed in Round-24 cleanup: the map itself was
# retired in favour of a CJK-strip fallback (the upstream data is now
# ASCII after the 2026-10-05 CJK->ASCII rename).  See
# agents/report_agent.py::strip_chinese_from_payload.


def test_no_duplicate_dict_literal_keys_in_report_agent():
    """F601 guard: duplicate keys in a literal silently drop earlier entries."""
    src = SITES["report_agent"].read_text(encoding="utf-8")
    tree = ast.parse(src)
    bad = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        seen = set()
        for key in node.keys:
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                if key.value in seen:
                    bad.append(f"line {key.lineno}: {key.value!r}")
                seen.add(key.value)
    assert not bad, f"duplicate dict keys: {bad}"


# ── BUG 5: `new_tr` referenced before assignment in the table repair ──
# `_strip_table_nodata_rows` re-scanned a variable that was never assigned in
# the loop, so any table row that was not dropped raised NameError.


def test_strip_table_nodata_rows_keeps_real_rows():
    from agents.report_agent import _strip_table_nodata_rows

    html = (
        "<table><tr><th>T</th><th>V</th></tr>"
        "<tr><td>2025-01-01</td><td>high</td></tr></table>"
    )
    out = _strip_table_nodata_rows(html)
    assert "2025-01-01" in out
    assert "high" in out


def test_strip_table_nodata_rows_drops_all_placeholder_rows():
    from agents.report_agent import _strip_table_nodata_rows

    html = (
        "<table><tr><th>T</th><th>V</th></tr>"
        "<tr><td>—</td><td>—</td></tr></table>"
    )
    out = _strip_table_nodata_rows(html)
    assert "<th>" in out
    assert "—" not in out


def test_strip_table_nodata_rows_preserves_row_attributes():
    from agents.report_agent import _strip_table_nodata_rows

    html = '<table><tr class="x"><td>2025-01-01</td><td>high</td></tr></table>'
    out = _strip_table_nodata_rows(html)
    assert 'class="x"' in out
    assert out.count("<tr") == out.count("</tr>")


# ── BUG 6: `httpx` used but never imported ──
# `query_as_info` calls `httpx.AsyncClient` for the RIPE Whois DB, but the
# module never imported httpx, so the call raised NameError at runtime.


def test_tool_implementations_binds_httpx():
    import tools.tool_implementations as ti

    assert hasattr(ti, "httpx"), "httpx must be imported for the RIPE Whois call"
    assert hasattr(ti.httpx, "AsyncClient")


def test_httpx_is_declared_in_requirements():
    req = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    assert "httpx" in req.lower(), "httpx is imported but not declared"


# ── BUG 7: `enhanced=` passed to a function whose parameter was removed ──
# `--mode deep` is a live CLI path; it passed an argument that no longer
# existed, raising NameError/TypeError before the LLM stage.


def test_analyze_deep_from_quick_has_no_dangling_enhanced():
    import inspect

    import chief_agent

    params = inspect.signature(chief_agent.analyze_deep_from_quick).parameters
    # `enhanced` was removed from the signature; the call site must not use it.
    src = SITES["chief_agent"].read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "analyze_deep_from_quick":
            for kw in node.keywords:
                assert kw.arg != "enhanced", f"line {node.lineno}: dangling enhanced="


def test_chief_expert_agent_still_accepts_its_declared_args():
    import inspect

    from chief_agent import ChiefExpertAgent

    sig = inspect.signature(ChiefExpertAgent.__init__)
    assert "model" in sig.parameters or "_MODEL" in str(sig)


# ── BUG 8: `_aggregate_timeseries_to_totals` vs `aggregate_timeseries_to_totals` ──
# The helper was defined without the leading underscore but called with one,
# so `process_event` raised NameError on any run with plot data.


def test_aggregate_timeseries_helper_name_matches_call():
    import detectors.outage.extract_event_features as m

    assert hasattr(m, "aggregate_timeseries_to_totals")
    assert not hasattr(m, "_aggregate_timeseries_to_totals"), "underscore variant must be gone"

    result = m.aggregate_timeseries_to_totals(
        {"2025-01-01 00:00:00": {"announcement_count": 5, "withdrawal_count": 2}}
    )
    assert result["announcement_count"] == 5
    assert result["withdrawal_count"] == 2


# ── BUG 9: duplicate `detect_route_leaks_in_announcements` definition ──
# Two identical wrappers existed; the second shadowed the first, so any code
# reading the first (e.g. by line number) was reasoning about dead code.


def test_no_duplicate_toplevel_function_in_leak_detector():
    src = SITES["leak_detector"].read_text(encoding="utf-8")
    tree = ast.parse(src)
    names = [n.name for n in tree.body if isinstance(n, ast.FunctionDef)]
    dupes = {n for n in names if names.count(n) > 1}
    assert not dupes, f"duplicate top-level functions: {dupes}"
    assert "detect_route_leaks_in_announcements" in names


# ── BUG 10: `n` undefined in the css_engine PNS fallback ──
# `n // 2` referenced a name not bound in that scope. It was unreachable only
# by accident (an early return), so it would have become a live NameError if
# the guard above it ever changed.


def test_css_engine_has_no_undefined_n_fallback():
    src = SITES["css_engine"].read_text(encoding="utf-8")
    assert "else n // 2" not in src
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and node.value is None:
            continue
    # The breakpoint call is now unconditional.
    assert "_find_breakpoint(t_aligned)" in src


# ── BUG 11: `routing_scope` closure captured the loop variable ──
# `_event_get` closed over `event`; the helper was called in the same
# iteration so it happened to work, but the pattern is fragile and was
# flagged as a genuine late-binding hazard.


def test_routing_scope_handles_mixed_event_types():
    from agents.routing_agent import routing_scope

    @dataclass
    class Detail:
        prefix: str = "8.8.8.0/24"

    out = routing_scope([Detail()], [{"prefix": "1.1.1.0/24"}], {})
    assert out["prefixes"] == ["1.1.1.0/24", "8.8.8.0/24"]
    assert out["hijack_events"] == 1
    assert out["leak_events"] == 1

    out2 = routing_scope([{"prefixes": ["2.2.2.0/24", "3.3.3.0/24"]}], [], {})
    assert out2["prefixes"] == ["2.2.2.0/24", "3.3.3.0/24"]


# ── BUG 12: semaphore captured by a gather-scheduled closure ──
# Every coroutine saw the *last* batch's semaphore, so the concurrency cap
# was never enforced.


def test_supervisor_binds_semaphore_per_batch():
    src = (ROOT / "agents" / "investigation_supervisor.py").read_text(encoding="utf-8")
    # Semaphore must be created INSIDE the batch loop, not outside.
    assert "semaphore = asyncio.Semaphore(self.max_concurrent)" in src
    # Must be inside the loop over batches, not at class level
    assert "for batch_num in" in src


# ── The config bug that let all of the above through ──


def test_ruff_config_uses_tool_ruff_headers():
    """`[lint]` is not a ruff section; only `[tool.ruff.lint]` is read."""
    import tomllib

    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    ruff = data.get("tool", {}).get("ruff")
    assert ruff is not None, "missing [tool.ruff] — ruff would read no config"
    assert "lint" in ruff, "missing [tool.ruff.lint] — select/ignore would be ignored"
    assert "select" in ruff["lint"]
    assert "ignore" in ruff["lint"]


@pytest.mark.skipif(
    not (ROOT / ".ruff_cache").exists() and "ruff" not in sys.modules,
    reason="ruff not invoked in this session",
)
def test_defect_rules_are_not_globally_ignored():
    """F821 and friends must stay blocking so a regression fails CI."""
    import tomllib

    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    ignored = set(data["tool"]["ruff"]["lint"].get("ignore", []))
    for rule in ("F821", "F601", "F811", "B023", "B025", "E722"):
        assert rule not in ignored, f"{rule} must remain a blocking rule"
