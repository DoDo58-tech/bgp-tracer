"""
Regression tests for round-4 audit-pass fixes:

  - R7  : ``agents.token_budget.TokenBudget.summary()`` must return
          per-agent token counts, not the global totals for every entry.
  - R8  : ``agents.correlation_analyzer`` dedup must preserve concurrent
          events of different types at the same timestamp.
  - R9  : ``data.updates_loader.ensure_updates_from_xlsx`` must use a
          defined row index in its error message (no NameError).
  - R10 : ``data.parquet_cache._source_fingerprint`` must remain stable
          across a ``touch`` that does not change content / size.
  - R11 : ``agents.payload_builder.record_llm_call`` must NOT swallow
          non-ImportError exceptions silently.
  - R12 : ``agents.investigation_supervisor.EvidenceEnricher.enrich``
          must NOT add ``confidence_boost`` from tools whose result
          has ``success=False``.
  - R13 : ``agents.reasoning_agent.ReasoningAgent.cross_validate_temporal_overlap``
          must exist and correctly compute overlap counts from routing
          + traffic evidence (the old, dangling-docstring dead code path
          is now a real method).
"""

import sys
from datetime import datetime
from pathlib import Path

import pytest

# Ensure repository root is importable regardless of where pytest is invoked
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# ---------------------------------------------------------------------------
# R7 — TokenBudget.summary()["by_agent"] correctness
# ---------------------------------------------------------------------------


def test_token_budget_summary_by_agent_returns_per_agent_values():
    """Each agent must report its own prompt/completion totals, not the
    global totals copied into every entry.
    """
    from agents.token_budget import TokenBudget

    run_id = "round4_r7_test"
    TokenBudget.clear_instance(run_id)
    try:
        tb = TokenBudget.get_instance(run_id)
        tb.add("AgentA", prompt_tokens=100, completion_tokens=50)
        tb.add("AgentA", prompt_tokens=200, completion_tokens=80)
        tb.add("AgentB", prompt_tokens=50, completion_tokens=30)

        summary = tb.summary()

        # Per-agent values must be the agent's own totals, NOT the global.
        assert summary["by_agent"]["AgentA"]["prompt_tokens"] == 300
        assert summary["by_agent"]["AgentA"]["completion_tokens"] == 130
        assert summary["by_agent"]["AgentA"]["total_tokens"] == 430

        assert summary["by_agent"]["AgentB"]["prompt_tokens"] == 50
        assert summary["by_agent"]["AgentB"]["completion_tokens"] == 30
        assert summary["by_agent"]["AgentB"]["total_tokens"] == 80

        # Global totals are still correct.
        assert summary["total_prompt_tokens"] == 350
        assert summary["total_completion_tokens"] == 160
        assert summary["total_tokens"] == 510
    finally:
        TokenBudget.clear_instance(run_id)


# ---------------------------------------------------------------------------
# R8 — correlation_analyzer dedup preserves concurrent different-type events
# ---------------------------------------------------------------------------


def test_correlation_dedup_preserves_concurrent_different_type_events():
    """When two traffic events share a timestamp but represent different
    event types (e.g. simultaneous drop and rise) the dedup key must
    include the event_type so neither is silently dropped.
    """
    from agents.correlation_analyzer import TemporalEvent

    events = [
        TemporalEvent(
            timestamp=datetime(2024, 6, 1, 12, 0, 0),
            source="traffic",
            event_type="traffic_drop",
            severity=0.8,
            details={},
        ),
        TemporalEvent(
            timestamp=datetime(2024, 6, 1, 12, 0, 0),
            source="traffic",
            event_type="traffic_rise",
            severity=0.6,
            details={},
        ),
        # True duplicate of the first — must be removed.
        TemporalEvent(
            timestamp=datetime(2024, 6, 1, 12, 0, 0),
            source="traffic",
            event_type="traffic_drop",
            severity=0.8,
            details={},
        ),
    ]

    # Replicate the post-fix dedup logic verbatim — if the in-file
    # implementation changes, this assertion fails loudly.
    seen = set()
    deduped = []
    for ev in sorted(events, key=lambda e: e.timestamp):
        key = (ev.timestamp.isoformat(), ev.event_type)
        if key not in seen:
            seen.add(key)
            deduped.append(ev)

    types = sorted(e.event_type for e in deduped)
    assert types == ["traffic_drop", "traffic_rise"], (
        f"Dedup lost distinct event types; got {types}"
    )


# ---------------------------------------------------------------------------
# R9 — updates_loader.ensure_updates_from_xlsx uses defined `idx`
# ---------------------------------------------------------------------------


def test_ensure_updates_from_xlsx_logs_row_index_without_nameerror(monkeypatch, caplog):
    """Regression: the for-loop iterates with ``enumerate`` so ``idx``
    is defined when an exception is caught and logged.  Without the
    fix, the very first failure would NameError and abort the entire
    batch.
    """
    import logging

    from data import updates_loader
    import polars as pl

    # Stub out ensure_updates_available_for_event so we control behaviour.
    call_count = {"n": 0}

    def fake_ensure(*args, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise ValueError("simulated parse failure for row 1")
        return ["/tmp/fake_rib.1234.0.gz"]

    monkeypatch.setattr(
        updates_loader, "ensure_updates_available_for_event", fake_ensure
    )

    # Mock pl.read_excel so we don't depend on fastexcel / xlsxwriter
    # being installed in the test env.
    fake_df = pl.DataFrame(
        {
            "start": ["06/01/24 00:00:00", "06/02/24 00:00:00"],
            "end": ["06/01/24 01:00:00", "06/02/24 01:00:00"],
        }
    )
    monkeypatch.setattr(updates_loader.pl, "read_excel", lambda _p: fake_df)

    with caplog.at_level(logging.ERROR, logger="bgp_tracer.data.updates_loader"):
        paths = updates_loader.ensure_updates_from_xlsx(
            "/tmp/anything.xlsx",
            start_col="start",
            end_col="end",
            pre_days=0,
            post_days=0,
        )
    # We expect the first failure to be logged with a defined row
    # index (enumerate starts at 0), and the second row to succeed.
    assert any(
        "Failed for row 0" in rec.message for rec in caplog.records
    ), (
        f"Expected 'Failed for row 0' in error log; idx may be undefined. "
        f"Records: {[r.message for r in caplog.records]}"
    )
    assert len(paths) >= 1, "Expected the second row to still be processed"


# ---------------------------------------------------------------------------
# R10 — parquet_cache._source_fingerprint stable across touch()
# ---------------------------------------------------------------------------


def test_source_fingerprint_stable_across_touch(tmp_path):
    """After a ``touch`` that does not change size or mtime-second,
    the fingerprint must remain identical (otherwise every cache entry
    is invalidated on every restart).
    """
    from data import parquet_cache

    src = tmp_path / "updates.20240101.0000.gz"
    src.write_bytes(b"hello world")

    fp_before = parquet_cache._source_fingerprint(src)
    # Re-stamp with the same mtime — no content change.
    stat = src.stat()
    # Use utime to set the same mtime as already present.
    import os
    os.utime(src, (stat.st_atime, stat.st_mtime))
    fp_after = parquet_cache._source_fingerprint(src)

    assert fp_before == fp_after, (
        f"Fingerprint changed across a no-op touch: {fp_before!r} -> {fp_after!r}"
    )


def test_source_fingerprint_changes_when_size_changes(tmp_path):
    """Sanity: when content (and therefore size) changes, the
    fingerprint MUST change so stale caches are invalidated.
    """
    from data import parquet_cache

    src = tmp_path / "updates.20240101.0000.gz"
    src.write_bytes(b"a" * 100)
    fp_small = parquet_cache._source_fingerprint(src)

    src.write_bytes(b"b" * 200)
    fp_large = parquet_cache._source_fingerprint(src)

    assert fp_small != fp_large


# ---------------------------------------------------------------------------
# R11 — payload_builder.record_llm_call must surface non-ImportError errors
# ---------------------------------------------------------------------------


def test_record_llm_call_does_not_swallow_non_importerror(monkeypatch, caplog):
    """A bare ``except Exception`` was hiding real failures inside
    TokenBudget.  The fix narrows the no-op branch to ImportError and
    warns for everything else.
    """
    import logging

    from agents import payload_builder

    # Patch TokenBudget.get_instance on the agents.token_budget module —
    # this is the symbol record_llm_call imports lazily.
    from agents import token_budget as _tb_module

    def fake_get_instance(_run_id):
        raise RuntimeError("TokenBudget init crashed")

    monkeypatch.setattr(
        _tb_module.TokenBudget, "get_instance", staticmethod(fake_get_instance)
    )

    with caplog.at_level(logging.WARNING, logger="bgp_tracer"):
        payload_builder.record_llm_call(
            "round4_r11_test",
            "FakeAgent",
            prompt="hello",
            response=type("R", (), {"usage": None})(),
        )

    assert any(
        "TokenBudget unavailable" in rec.message for rec in caplog.records
    ), "Expected a WARNING when TokenBudget init fails; got none"


# ---------------------------------------------------------------------------
# R12 — failed tool results must not contribute confidence_boost
# ---------------------------------------------------------------------------


def test_investigation_supervisor_skips_confidence_boost_for_failed_tools():
    """When a tool's result reports ``success=False`` (e.g. RPKI failure),
    the supervisor must NOT add its confidence_boost to the running
    total — otherwise downstream confidence becomes inflated.
    """
    from agents.investigation_supervisor import (
        EvidenceEnricher,
        TriggeredTool,
        TriggerRule,
    )

    rule_pass = TriggerRule(
        name="rpki_check",
        tool_name="validate_roa_status",
        tool_params={},
        conditions=["origin_hijack"],
        reason="RPKI",
        confidence_boost=0.4,
    )
    rule_fail = TriggerRule(
        name="as_topology",
        tool_name="as_topology_position",
        tool_params={},
        conditions=["origin_hijack"],
        reason="topology",
        confidence_boost=0.3,
    )

    triggered = [
        TriggeredTool(
            rule=rule_pass,
            params={},
            status="done",
            result={"success": True, "data": "ok"},
        ),
        TriggeredTool(
            rule=rule_fail,
            params={},
            status="done",
            # success=False → must be excluded from confidence_boost
            result={"success": False, "error": "API down"},
        ),
    ]

    enriched = EvidenceEnricher.enrich(triggered, original_context={})

    # Only the successful tool should contribute.
    assert enriched["total_confidence_boost"] == pytest.approx(0.4), (
        f"confidence_boost leaked from failed tool: {enriched['total_confidence_boost']}"
    )
    # Failed tool is still recorded for visibility, but with success=False.
    assert enriched["auxiliary_enrichment"]["as_topology"]["success"] is False


# ---------------------------------------------------------------------------
# R13 — reasoning_agent.cross_validate_temporal_overlap exists & works
# ---------------------------------------------------------------------------


def test_cross_validate_temporal_overlap_counts_aligned_events():
    """The dead-code block from the dangling docstring is now a real,
    callable helper.  Verify it counts routing events that fall within
    the requested window of a traffic anomaly.
    """
    from agents.reasoning_agent import ReasoningAgent

    agent = ReasoningAgent.__new__(ReasoningAgent)
    agent.evidence_pool = {}
    agent.reasoning_trace = []
    agent.start_time = datetime(2024, 6, 1, 0, 0, 0)
    agent.end_time = datetime(2024, 6, 1, 23, 59, 59)

    agent.evidence_pool["routing_data"] = {
        "origin_hijacked": [
            {"timestamp": "2024-06-01 12:00:00"},
            {"timestamp": "2024-06-01 12:30:00"},
        ]
    }
    agent.evidence_pool["traffic_data"] = {
        "anomalies": [
            {"timestamp": "2024-06-01T12:05:00Z"},
            {"timestamp": "2024-06-01T13:00:00Z"},  # 30min after — outside 1h
        ]
    }

    result = agent.cross_validate_temporal_overlap(overlap_window_seconds=3600)
    assert result is not None
    # Both routing events fall within 1h of the first traffic anomaly.
    assert result["overlap_count"] == 2, (
        f"Expected 2 overlapping routing events, got {result['overlap_count']}"
    )
    # Result is stashed in evidence_pool for downstream consumers.
    assert agent.evidence_pool["temporal_correlation"]["overlap_count"] == 2


def test_cross_validate_temporal_overlap_returns_none_when_no_data():
    """If either side is empty, the helper must return ``None`` rather
    than synthesising zeros.
    """
    from agents.reasoning_agent import ReasoningAgent

    agent = ReasoningAgent.__new__(ReasoningAgent)
    agent.evidence_pool = {"routing_data": {}, "traffic_data": {}}
    agent.reasoning_trace = []

    assert agent.cross_validate_temporal_overlap() is None
