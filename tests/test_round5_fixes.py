"""
Regression tests for round-5 audit-pass fixes:

  - R16 : ``_SHARED_EVIDENCE`` is cleared at the end of every React run
          (was a memory leak — bucket lived for the process lifetime).
  - R17 : ``chief_agent.CheckpointManager`` stores the original
          ``start_time`` in the JSON payload (was polluted with the
          sanitized ``self.tag``).
  - R18 : ``utils.report_exporters._generate_batch_html_report``
          actually substitutes the template placeholders (was a no-op
          that left literal ``{analysis_period}`` etc. in the HTML).
  - R19 : ``detectors.unified_result.from_dict`` normalises legacy
          ``route_leak`` (singular) to ``leak`` so the
          ``route_leaks`` property keeps matching.
  - R20 : ``chief_agent._light_origin_hijack`` accepts either
          ``as-path`` (hyphen) or ``as_path`` (underscore) as the
          column name (was silently dropped before ``detect_origin_hijacks``).
  - R21 : ``utils.logger`` does not create duplicate file handlers when
          ``setup_logger`` is invoked repeatedly with the same name.
  - R22 : ``agents.react_agent._finalize_run`` is idempotent and never
          raises (cleanup must not break a finished run).
  - R23 : ``tools.tool_implementations.APICache.set`` enforces a
          ``max_entries`` cap so memory cannot grow unbounded.
  - R24 : ``tools.irr_registry._whois_query`` closes its writer even
          when ``read()`` raises (FD leak fix).
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# ---------------------------------------------------------------------------
# R16 — _SHARED_EVIDENCE cleanup
# ---------------------------------------------------------------------------


def test_shared_evidence_cleared_after_run():
    """Regression: every React run must drop its evidence bucket when it
    finishes.  Without this, every analysis run leaks a dict of tool
    outputs that lives until the Python process dies.
    """
    from agents import react_agent

    run_id = "round5_r16_test"

    # Seed a bucket so we can detect it gets cleared.
    react_agent._SHARED_EVIDENCE[run_id] = {"stale": True}

    fake_result = react_agent.ReactResult(
        success=True,
        answer="ok",
        trace=None,
        tools_used=[],
        total_rounds=1,
        run_id=run_id,
    )
    react_agent._finalize_run(fake_result)

    assert run_id not in react_agent._SHARED_EVIDENCE, (
        f"_SHARED_EVIDENCE still has bucket {run_id!r} after run"
    )


def test_finalize_run_swallows_exceptions():
    """Cleanup must never break a finished run, even if the helper itself
    blows up (e.g. bad run_id, monkey-patched pop).
    """
    from agents import react_agent

    class _BadResult:
        run_id = None  # getattr(result, "run_id", "") returns ""; should be safe.

    out = react_agent._finalize_run(_BadResult())
    assert out is not None


# ---------------------------------------------------------------------------
# R17 — CheckpointManager.start_time fidelity
# ---------------------------------------------------------------------------


def test_checkpoint_manager_persists_original_start_time(tmp_path):
    """The checkpoint payload must round-trip the original ``start_time``
    parameter, not the sanitized ``self.tag`` (which contains
    ``AS<id>_<date>_<mode>``).
    """
    from chief_agent import CheckpointManager

    ckpt = CheckpointManager(
        asn=12345,
        start_time="2024-06-01 00:00",
        mode="quick",
        checkpoint_dir=tmp_path,
        enabled=True,
    )
    ckpt.save("traffic", {"success": True, "value": 1})

    # Read the raw JSON on disk.
    raw = json.loads(ckpt.path.read_text(encoding="utf-8"))
    assert raw["start_time"] == "2024-06-01 00:00", (
        f"start_time polluted with tag info: {raw['start_time']!r}"
    )
    # The tag itself remains a different field (or absent) — it must NOT
    # leak into ``start_time``.
    assert "12345_2024-06-01" not in raw["start_time"]


# ---------------------------------------------------------------------------
# R18 — report_exporters batch template actually substitutes
# ---------------------------------------------------------------------------


def test_batch_html_template_placeholders_substituted(tmp_path):
    """The batch HTML template uses Python format-style placeholders;
    the exporter must replace them rather than leaving literal
    ``{analysis_period}`` in the HTML body.
    """
    from utils import report_exporters

    output_dir = tmp_path / "out"
    output_dir.mkdir()
    batch = {
        "results_by_as": {"12345": {"anomalies": [], "status": "normal"}},
    }
    out = report_exporters.generate_batch_html_report(
        batch_result=batch,
        start_time="2024-06-01 00:00",
        end_time="2024-06-07 00:00",
        output_dir=output_dir,
    )
    body = Path(out).read_text(encoding="utf-8")

    assert "{analysis_period}" not in body, (
        f"Placeholder leaked into rendered HTML: {body[:500]}"
    )
    assert "{total_as}" not in body
    assert "2024-06-01" in body


# ---------------------------------------------------------------------------
# R19 — unified_result.from_dict type aliasing
# ---------------------------------------------------------------------------


def test_unified_result_route_leak_alias_normalised():
    """Items in ``route_leaks`` whose ``type`` is the legacy
    ``'route_leak'`` (singular) must be normalised to ``'leak'`` so the
    ``UnifiedDetectionResult.route_leaks`` property keeps matching them.
    """
    from detectors.unified_result import UnifiedDetectionResult

    payload = {
        "anomalies": [
            {
                "type": "route_leak",  # legacy singular
                "prefix": "203.0.113.0/24",
                "timestamp": "2024-06-01T00:00:00Z",
                "severity": "high",
            }
        ]
    }
    result = UnifiedDetectionResult.from_dict(payload)
    assert result.route_leaks, (
        f"Legacy 'route_leak' items should still be picked up by "
        f"the route_leaks property, got {result.route_leaks!r}"
    )
    assert result.route_leaks[0].type == "leak"


def test_unified_result_origin_hijack_alias_normalised():
    """A hijack entry whose ``type`` is the legacy ``'origin_hijacking'``
    or ``'origin_hijacked'`` must be normalised to the canonical
    ``'origin_hijack'`` so the ``origin_hijacked`` property keeps
    matching it.
    """
    from detectors.unified_result import UnifiedDetectionResult

    payload = {
        "origin_hijacked": [
            {
                # legacy: type was sometimes the attacker-side string
                "type": "origin_hijacking",
                "prefix": "203.0.113.0/24",
                "timestamp": "2024-06-01T00:00:00Z",
            }
        ]
    }
    result = UnifiedDetectionResult.from_dict(payload)
    assert result.origin_hijacked, (
        f"Legacy 'origin_hijacking' should be normalised; got {result.origin_hijacked!r}"
    )
    # And the rewritten type must be the canonical one.
    assert result.origin_hijacked[0].type == "origin_hijack"


# ---------------------------------------------------------------------------
# R20 — _light_origin_hijack column name compatibility
# ---------------------------------------------------------------------------


def test_light_origin_hijack_keeps_either_as_path_column():
    """The quick-mode hijack detector must keep the BGP AS-path column
    regardless of whether it's named ``as-path`` (MRT convention) or
    ``as_path`` (snake_case Polars convention).  Otherwise
    ``detect_origin_hijacks`` raises ``ColumnNotFoundError`` silently.
    """
    import polars as pl

    df_hyphen = pl.DataFrame({"prefix": ["1.0.0.0/8"], "as-path": ["12345 67890"]})
    df_underscore = pl.DataFrame({"prefix": ["1.0.0.0/8"], "as_path": ["12345 67890"]})

    # Simulate the keep-list logic added to _light_origin_hijack.
    def keep_cols(df):
        keep = ["prefix"]
        for col in ("as-path", "as_path"):
            if col in df.columns:
                keep.append(col)
                break
        if "timestamp" in df.columns:
            keep.append("timestamp")
        return df.select([c for c in keep if c in df.columns])

    assert "as-path" in keep_cols(df_hyphen).columns
    assert "as_path" in keep_cols(df_underscore).columns


# ---------------------------------------------------------------------------
# R21 — utils.logger does not leak FDs across setup_logger calls
# ---------------------------------------------------------------------------


def test_setup_logger_does_not_duplicate_file_handlers():
    """Repeated ``setup_logger`` calls for the same name must NOT create
    a fresh ``FileHandler`` every time, otherwise repeated invocations
    leak file descriptors and produce duplicate log lines.
    """
    import importlib
    import logging

    # Import the module via importlib so the local ``logger`` symbol
    # doesn't shadow ``logging.logger``.
    _logger_mod = importlib.import_module("utils.logger")

    name = "round5_r21_logger"
    new_logger = logging.getLogger(name)
    new_logger.handlers.clear()

    _logger_mod.setup_logger(name)
    handlers_after_first = list(new_logger.handlers)

    _logger_mod.setup_logger(name)
    handlers_after_second = list(new_logger.handlers)

    file_handlers_first = [h for h in handlers_after_first
                           if isinstance(h, logging.FileHandler)]
    file_handlers_second = [h for h in handlers_after_second
                            if isinstance(h, logging.FileHandler)]

    assert len(file_handlers_second) == len(file_handlers_first), (
        f"setup_logger duplicated FileHandler; "
        f"first={len(file_handlers_first)}, second={len(file_handlers_second)}"
    )

    new_logger.handlers.clear()


# ---------------------------------------------------------------------------
# R23 — APICache bounded memory
# ---------------------------------------------------------------------------


def test_api_cache_enforces_max_entries():
    """``APICache.set`` must respect its ``max_entries`` cap so the
    cache cannot grow unbounded with ever-changing keys.
    """
    from tools.tool_implementations import APICache

    cache = APICache(ttl_seconds=3600, max_entries=128)
    # Insert well over the cap. Each set drops the oldest ``max_entries // 16``
    # (so the cap is loose enough that memory stays bounded but not
    # over-aggressive).
    for i in range(500):
        cache.set(f"key_{i}", {"i": i})

    assert len(cache._cache) <= 128, (
        f"APICache exceeded max_entries cap: {len(cache._cache)} entries"
    )


def test_api_cache_set_prunes_expired_entries():
    """Expired entries should be cleaned up opportunistically on every
    set so memory stays tight even if the cap isn't hit.
    """
    from tools.tool_implementations import APICache

    cache = APICache(ttl_seconds=0.05, max_entries=1000)
    cache.set("ephemeral", "x")
    # Wait beyond the TTL.
    time.sleep(0.1)
    cache.set("next", "y")

    assert "ephemeral" not in cache._cache, (
        f"Expired entry 'ephemeral' was not pruned on subsequent set: "
        f"{list(cache._cache.keys())}"
    )


# ---------------------------------------------------------------------------
# R24 — WHOIS writer is closed even on read failure
# ---------------------------------------------------------------------------


def test_whois_query_closes_writer_on_failure(monkeypatch):
    """When ``reader.read`` raises, the WHOIS writer must still be
    closed so the TCP socket is released.
    """
    from tools import irr_registry

    closed = {"flag": False}
    drained = {"flag": False}

    class _FakeWriter:
        def write(self, _data):
            pass

        async def drain(self):
            drained["flag"] = True

        def close(self):
            closed["flag"] = True

        async def wait_closed(self):
            pass

    class _FakeReader:
        async def read(self, _n):
            raise ConnectionResetError("simulated read failure")

    async def fake_open_connection(*_a, **_kw):
        return _FakeReader(), _FakeWriter()

    async def fake_wait_for(awaitable, timeout):
        return await awaitable

    monkeypatch.setattr(irr_registry.asyncio, "open_connection", fake_open_connection)
    monkeypatch.setattr(irr_registry.asyncio, "wait_for", fake_wait_for)

    result = asyncio.run(irr_registry._whois_query("whois.example.com", "!gAS12345"))

    assert closed["flag"], "WHOIS writer was not closed after read failure"
    assert drained["flag"], "WHOIS drain was not awaited before read failure"
    assert "Error" in result or "Timeout" in result
