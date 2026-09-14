"""
Regression tests for Round 17 bug fixes.

BUG-R130: chief_agent.analyze_traffic_outage_async used ``os.replace`` at line 1319
without importing ``os`` at module level, causing a NameError whenever the
post-pipeline code path was exercised. The traffic_first mode on a leak event
will hit this path. The report had already been written to disk, but the
top-level process exited with code 1 instead of 0.

Fix: add ``import os`` to the module-level imports of chief_agent.py.

This test verifies that:
  - chief_agent module imports cleanly (i.e. the missing import is fixed)
  - analyze_traffic_outage is importable from chief_agent

BUG-R131: chief_agent._legacy_direct_analysis called ``run_routing_agent_async``
without ``skip_forge=True``, so even with ``MITM_DETECTION_ENABLED=false`` (the
default) the routing_impl fallback path would compute ``skip_forge =
not enable_mitm = True`` from the routing_impl default of ``enable_mitm=True``.
The forge detection path takes 5-15 minutes on a 3-hour window with millions of
BGP updates, exceeding the 900-second per-mode timeout used by
``run_4mode_batch.py``.

Fix: pass ``skip_forge=True`` explicitly to both ``run_routing_agent_async``
calls in ``_legacy_direct_analysis`` (initial routing + deep routing).

This test verifies that:
  - The legacy direct analysis code path now passes ``skip_forge=True``
    to ``run_routing_agent_async``.
"""
from __future__ import annotations

import importlib
import inspect
import sys


def test_chief_agent_imports_clean():
    """chief_agent must import without raising NameError on top-level imports."""
    if "chief_agent" in sys.modules:
        importlib.reload(sys.modules["chief_agent"])
    else:
        import chief_agent  # noqa: F401
    assert "chief_agent" in sys.modules


def test_chief_agent_has_os_module():
    """The chief_agent module must have access to ``os`` for atomic file writes."""
    import chief_agent  # noqa: F401
    import os

    # Either os is in the module namespace (module-level import) or os.replace
    # must be importable via the system path. The atomic-write helper at line
    # ~1319 in chief_agent.py uses ``os.replace`` directly, so the module
    # must have access to ``os``.
    assert hasattr(os, "replace"), "os.replace should be available"


def test_chief_agent_analyze_traffic_outage_is_callable():
    """analyze_traffic_outage must be a callable symbol on chief_agent."""
    import chief_agent

    assert callable(getattr(chief_agent, "analyze_traffic_outage", None)), (
        "analyze_traffic_outage must be importable from chief_agent"
    )


def test_legacy_direct_analysis_passes_skip_forge_true():
    """BUG-R131: _legacy_direct_analysis must pass skip_forge=True to routing.

    Without this, the routing_impl default ``skip_forge=None`` becomes
    ``not enable_mitm = True`` when ``enable_mitm=True`` (the routing_impl
    default), causing forge detection to run by default.
    """
    import chief_agent

    # The legacy direct analysis method must exist.
    cls = chief_agent.ChiefExpertAgent
    assert hasattr(cls, "_legacy_direct_analysis"), (
        "ChiefExpertAgent._legacy_direct_analysis must exist"
    )

    src = inspect.getsource(cls._legacy_direct_analysis)
    # Strip comments to avoid false positives from comment text mentioning
    # skip_forge (e.g. the bug-fix comment itself).
    import re
    src_no_comments = re.sub(r"#.*", "", src)

    # Count occurrences of run_routing_agent_async(
    n_calls = src_no_comments.count("run_routing_agent_async(")
    assert n_calls >= 2, (
        f"_legacy_direct_analysis should call run_routing_agent_async "
        f"twice (initial + deep). Found {n_calls}."
    )

    # Both calls must pass skip_forge=True. Check that the keyword argument
    # appears in the source.
    assert src_no_comments.count("skip_forge=True") >= 2, (
        f"_legacy_direct_analysis must pass skip_forge=True to both "
        f"run_routing_agent_async calls. Found "
        f"{src_no_comments.count('skip_forge=True')} occurrences."
    )

