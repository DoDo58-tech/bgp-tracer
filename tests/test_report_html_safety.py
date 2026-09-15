"""Regression tests for the report rendering pipeline.

Covers four production bugs that operators observed on 2026-09-13 / 09-14:

  1. Reports whose body lost all leading ``<`` characters (Qwen / GLM
     output ``div class="x">`` instead of ``<div class="x">``) displayed as
     raw source text. The ``_repair_missing_lt`` helper must restore the
     brackets without breaking well-formed HTML.

  2. The injected traffic-plot image occasionally exceeded the surrounding
     report width because tables lacked ``table-layout: fixed`` and the
     ``<img>`` had ``max-width:100%`` only at the element level. The
     ``inject_traffic_plot`` function now also injects a width-alignment
     ``<style>`` block so the chart and tables share a single width cap.

  3. The HTML produced by ``_strip_nodata_artifacts`` is not always
     well-formed — when the LLM emits ``<table`` without a closing ``>``
     the regex pipeline can produce invalid HTML. ``validate_html_balance``
     must catch this so callers can fall back to the deterministic HTML
     renderer instead of writing a corrupt report.

  4. BUG-R117 (2026-09-14): the standalone ``generate_report_html`` entry
     point skipped ``_repair_missing_lt``, so reports generated via
     ``generate_integrated_report`` (and other callers that bypass the
     ReportAgent workflow) had their ``<`` characters dropped in the body
     and showed up as raw source text. The standalone path now calls
     ``_repair_missing_lt`` and ``_repair_missing_lt`` also restores the
     leading ``<`` from ``<!-- ... -->`` HTML comment markers.
"""

from __future__ import annotations

import asyncio
import base64
import os
import re
import sys
from pathlib import Path

# Make sure the project root is importable when pytest is run from the repo root.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest


# ---------------------------------------------------------------------------
# _repair_missing_lt
# ---------------------------------------------------------------------------

def test_repair_missing_lt_restores_open_and_close_brackets():
    from agents.report_agent import _repair_missing_lt, validate_html_balance

    # 180449-style damage: ``<`` dropped before <div>, <p>, <span>, <h1>
    broken = (
        '<!DOCTYPE html>'
        '<html><head><title>x</title></head><body>'
        'div class="report-container">'
        'div class="header">'
        'h1>Incident Report/h1>'
        'div class="meta">Target AS: 12479/div>'
        '/div>'
        '/div>'
        '</body></html>'
    )

    repaired = _repair_missing_lt(broken)

    # Openers are prefixed with ``<``; closers use the proper ``</tag>`` form.
    assert "<div class=" in repaired
    assert "<h1>" in repaired
    assert "</h1>" in repaired
    assert "</div>" in repaired
    # The well-formed version must parse cleanly.
    ok, problems = validate_html_balance(repaired)
    assert ok, f"expected balanced HTML, got problems={problems[:3]}"


def test_repair_missing_lt_does_not_double_doctype():
    from agents.report_agent import _repair_missing_lt

    html = "<!DOCTYPE html><html><body><p>x</p></body></html>"
    repaired = _repair_missing_lt(html)
    # We should not produce "<!DOCTYPE <html>>" or other corruptions.
    assert "<!DOCTYPE <" not in repaired
    assert repaired.startswith("<!DOCTYPE html>")


def test_repair_missing_lt_preserves_pre_existing_brackets():
    from agents.report_agent import _repair_missing_lt

    html = "<html><body><p>fine</p></body></html>"
    # Already valid: must remain byte-identical (modulo no-op replacements).
    assert _repair_missing_lt(html) == html


def test_repair_missing_lt_restores_html_comment_openers():
    """BUG-R117 (2026-09-14): Qwen / GLM drop the leading ``<`` from
    ``<!-- SECTION -->`` HTML comment markers, leaving them as visible
    ``!-- SECTION -->`` text in the rendered report. ``_repair_missing_lt``
    must restore the missing ``<`` so the markers become true HTML comments.
    """
    from agents.report_agent import _repair_missing_lt

    broken = (
        "<!DOCTYPE html>"
        "<html><body>\n"
        "!-- HEADER -->\n"
        "div class=\"header\">\n"
        "  h1>Title/h1>\n"
        "/div>\n"
        "\n"
        "!-- EXECUTIVE SUMMARY -->\n"
        "p>Body text./p>\n"
        "</body></html>"
    )

    repaired = _repair_missing_lt(broken)

    # Both ``<!-- ... -->`` markers must be present, byte-for-byte.
    assert "<!-- HEADER -->" in repaired
    assert "<!-- EXECUTIVE SUMMARY -->" in repaired
    # No naked ``!--`` opener should remain at the start of a line.
    for line in repaired.split("\n"):
        assert not line.lstrip().startswith("!--"), (
            f"_repair_missing_lt left a naked ``!--`` opener: {line!r}"
        )
    # The body content is also repaired.
    assert "<div class=" in repaired
    assert "<h1>" in repaired
    assert "</h1>" in repaired
    assert "</div>" in repaired


def test_repair_missing_lt_restores_bare_openers_without_attributes():
    """BUG-R117 follow-up: Qwen / GLM also drop the leading ``<`` from
    bare openers with no attributes, e.g. ``h1>`` and ``p>``. The
    original regex required \\s (mandatory whitespace) before the
    attribute block, which let these through un-repaired.
    """
    from agents.report_agent import _repair_missing_lt

    broken = (
        "<!DOCTYPE html>"
        "<html><body>\n"
        "div class=\"header\">\n"
        "h1>Incident Report/h1>\n"
        "h2>Executive Summary/h2>\n"
        "p>Body text./p>\n"
        "/div>\n"
        "</body></html>"
    )

    repaired = _repair_missing_lt(broken)

    # All bare openers (with or without attributes) must be repaired.
    assert "<div class=" in repaired
    assert "<h1>" in repaired
    assert "<h2>" in repaired
    assert "<p>" in repaired
    assert "</h1>" in repaired
    assert "</h2>" in repaired
    assert "</p>" in repaired
    assert "</div>" in repaired
    # And no naked opentags should remain.
    for line in repaired.split("\n"):
        stripped = line.lstrip()
        # Skip CSS selectors (preceded by `{` or `.`).
        if stripped.startswith("{") or stripped.startswith("."):
            continue
        assert not re.match(r"^(html|head|body|div|p|span|strong|em|h1|h2|h3|h4|h5|h6|ul|ol|li|table|thead|tbody|tr|td|th|section|article|header|footer|main|blockquote|pre|code)\b", stripped), (
            f"_repair_missing_lt left a bare opener: {line!r}"
        )


def test_repair_missing_lt_does_not_double_existing_comment_brackets():
    """The repair must NOT turn a well-formed ``<!--`` into ``<<!--``."""
    from agents.report_agent import _repair_missing_lt

    html = "<html><body><!-- section --><p>x</p></body></html>"
    repaired = _repair_missing_lt(html)
    # No double-bracket artefacts.
    assert "<<!--" not in repaired
    assert "<!-- section -->" in repaired


def test_repair_missing_lt_skips_word_internal_tags():
    """Tag-like substrings inside natural language must NOT be promoted.

    Example: ``recommended<div>`` is a noun + a tag opener. We don't want
    to inject a stray ``<`` between them.
    """
    from agents.report_agent import _repair_missing_lt

    # ``recommended<div>`` → the word "recommended" precedes the tag. We
    # don't want to insert another ``<`` before ``<div>`` (it's already
    # well-formed). What we DO test: we don't insert one between "recommended"
    # and the existing "<div>".
    html = "<p>The recommended<div>x</div></p>"
    repaired = _repair_missing_lt(html)
    assert "recommended<div>x</div>" in repaired


# ---------------------------------------------------------------------------
# validate_html_balance
# ---------------------------------------------------------------------------

def test_validate_html_balance_accepts_well_formed_html():
    from agents.report_agent import validate_html_balance

    ok, problems = validate_html_balance(
        '<html><body><div><p>x</p></div></body></html>'
    )
    assert ok
    assert problems == []


def test_validate_html_balance_detects_unclosed_div():
    from agents.report_agent import validate_html_balance

    ok, problems = validate_html_balance(
        '<html><body><div><p>x</p></body></html>'
    )
    assert not ok
    assert any("div" in p for p in problems)


def test_validate_html_balance_detects_mismatched_close():
    from agents.report_agent import validate_html_balance

    # ``</p>`` appears without a matching opener.
    # (Note: <p> is HTML5-optional-end, so a stray </p> without an
    # opener is tolerated — browsers do the same.)
    ok, problems = validate_html_balance(
        '<html><body></p></body></html>'
    )
    # The doc is balanced per HTML5 implicit-close rules.
    assert ok


def test_validate_html_balance_void_tags_are_not_pushed():
    from agents.report_agent import validate_html_balance

    # ``<br>`` and ``<img>`` are void elements — they must not appear on the
    # unclosed-tag stack.
    ok, _ = validate_html_balance(
        '<html><body><br><img src="x"></body></html>'
    )
    assert ok


# ---------------------------------------------------------------------------
# inject_traffic_plot width alignment
# ---------------------------------------------------------------------------

def _fake_b64_png() -> str:
    """1x1 transparent PNG encoded as base64."""
    return base64.b64encode(
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
        b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06"
        b"\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\rIDATx"
        b"\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00"
        b"\x00IEND\xaeB`\x82"
    ).decode("ascii")


def test_inject_traffic_plot_adds_width_alignment_css():
    from agents.report_agent import inject_traffic_plot

    html = (
        '<!DOCTYPE html><html><head><title>x</title></head>'
        '<body><table><tr><td>AS12479</td></tr></table></body></html>'
    )
    out = inject_traffic_plot(html, _fake_b64_png())

    # The chart must be injected.
    assert "data:image/png;base64," in out
    # The width-alignment CSS must be present.
    assert "bt-chart-img" in out
    assert "table-layout:fixed" in out
    assert "word-break:break-word" in out
    # The chart must use the bt-chart-img class (so CSS kicks in).
    assert 'class="bt-chart-img"' in out


def test_inject_traffic_plot_is_idempotent_for_css():
    from agents.report_agent import inject_traffic_plot

    html = (
        '<!DOCTYPE html><html><head><title>x</title></head>'
        '<body><p>x</p></body></html>'
    )
    first = inject_traffic_plot(html, _fake_b64_png())
    second = inject_traffic_plot(first, _fake_b64_png())
    # Calling twice must not produce two <style> blocks or two charts.
    assert first.count("bt-tracer-width-align") == 1
    assert second.count("bt-tracer-width-align") == 1
    assert second.count("data:image/png;base64,") == 1


def test_inject_traffic_plot_strips_path_based_image_refs():
    from agents.report_agent import inject_traffic_plot

    html = (
        '<!DOCTYPE html><html><head><title>x</title></head>'
        '<body><img src="/data/bgp_tracer/results/traffic_plots/AS12479.png" />'
        '<p>x</p></body></html>'
    )
    out = inject_traffic_plot(html, _fake_b64_png())
    # The path-based ref must be gone (broken on other hosts), replaced by
    # exactly one base64 copy.
    assert "/data/bgp_tracer/results/traffic_plots" not in out
    assert out.count("data:image/png;base64,") == 1


# ---------------------------------------------------------------------------
# Blackboard write-once
# ---------------------------------------------------------------------------

def test_blackboard_writeonce_keeps_original_on_equivalent_writes():
    """Two semantically equivalent writes must NOT clobber each other."""
    from agents.core import Blackboard

    async def run():
        bb = Blackboard()
        # 401 hijack events
        a = {
            "origin_hijacked": [
                {"timestamp": "2024-01-03T14:54:29Z", "prefix": "2001:db8::/32"}
                for _ in range(401)
            ],
            "hijack_count": 401,
        }
        # Same payload plus a cosmetic analysis_timestamp field.
        b = dict(a)
        b["analysis_timestamp"] = "2026-09-13T18:24:00"

        await bb.write("routing", "result", a, _writer="first")
        await bb.write("routing", "result", b, _writer="second")

        out = await bb.read("routing", "result")
        # The original payload's signature fields must be preserved.
        assert out["hijack_count"] == 401
        assert len(out["origin_hijacked"]) == 401

    asyncio.run(run())


def test_blackboard_writeonce_rejects_divergent_writes():
    """A second write that drops events must NOT replace the original."""
    from agents.core import Blackboard

    async def run():
        bb = Blackboard()
        a = {
            "origin_hijacked": [
                {"timestamp": "2024-01-03T14:54:29Z", "prefix": "2001:db8::/32"}
                for _ in range(401)
            ],
            "hijack_count": 401,
        }
        # Divergent payload: 0 events (the bug operators observed).
        c = {"origin_hijacked": [], "hijack_count": 0}

        await bb.write("routing", "result", a, _writer="first")
        await bb.write("routing", "result", c, _writer="second")
        out = await bb.read("routing", "result")
        # Divergent write must be rejected — original kept.
        assert out["hijack_count"] == 401

    asyncio.run(run())


def test_blackboard_writeonce_allows_explicit_overwrite():
    """`_allow_overwrite=True` must let a divergent write through."""
    from agents.core import Blackboard

    async def run():
        bb = Blackboard()
        a = {"origin_hijacked": [{"timestamp": "t", "prefix": "p"}], "hijack_count": 1}
        c = {"origin_hijacked": [], "hijack_count": 0}
        await bb.write("routing", "result", a, _writer="first")
        await bb.write(
            "routing", "result", c, _writer="fallback", _allow_overwrite=True
        )
        out = await bb.read("routing", "result")
        assert out["hijack_count"] == 0

    asyncio.run(run())


def test_blackboard_update_section_also_protects_critical_keys():
    """update_section must respect the write-once guard for critical keys."""
    from agents.core import Blackboard

    async def run():
        bb = Blackboard()
        await bb.update_section(
            "routing",
            {
                "result": {
                    "origin_hijacked": [
                        {"timestamp": "t", "prefix": "p"} for _ in range(50)
                    ],
                    "hijack_count": 50,
                }
            },
            _writer="first",
        )
        await bb.update_section(
            "routing",
            {
                "result": {
                    "origin_hijacked": [],
                    "hijack_count": 0,
                }
            },
            _writer="second",
        )
        out = await bb.read("routing", "result")
        assert out["hijack_count"] == 50

    asyncio.run(run())


# ---------------------------------------------------------------------------
# BUG-R117: standalone generate_report_html must call _repair_missing_lt
# ---------------------------------------------------------------------------

def test_standalone_generate_report_html_calls_repair_missing_lt():
    """BUG-R117: the standalone ``generate_report_html`` entry point must
    invoke ``_repair_missing_lt`` on the LLM response, otherwise callers
    like ``generate_integrated_report`` produce reports whose body is
    rendered as raw source text.

    We assert the call exists in the source so this contract can't be
    accidentally removed by a future refactor.
    """
    import inspect
    import re as _re
    from agents.report_agent import generate_report_html

    src = inspect.getsource(generate_report_html)
    # Strip comments to avoid matching `# call _repair_missing_lt` docstrings.
    code_only = _re.sub(r"#.*", "", src)
    assert "_repair_missing_lt(" in code_only, (
        "standalone generate_report_html must invoke _repair_missing_lt on "
        "the LLM response; otherwise Qwen/GLM reports display as raw text "
        "(BUG-R117)."
    )


def test_repair_missing_lt_handles_bare_openers_without_attributes_via_lookahead():
    r"""BUG-R117 follow-up (Round 18): The new regex uses a lookahead (?=[ \t]*>)
    to fire even when the opener has no attributes (e.g. ``h1>`` / ``<p>``).
    The old regex required \s before the attribute block, which left bare
    openers un-repaired. This is tested via the same _repair_missing_lt fixture.
    """
    from agents.report_agent import _repair_missing_lt

    # LLM output with both attribute-bearing and bare openers, all missing ``<``.
    broken = (
        "<!DOCTYPE html><html><body>\n"
        "div class=\"report\">\n"
        "  h1>Network Incident Report/h1>\n"
        "  h2>Executive Summary/h2>\n"
        "  p>No anomalies detected./p>\n"
        "  div class=\"section\">\n"
        "    p>Body text here./p>\n"
        "  /div>\n"
        "/body>/html>"
    )
    repaired = _repair_missing_lt(broken)

    # All openers must have their leading ``<`` restored.
    assert "<h1>" in repaired, "h1 opener not repaired"
    assert "<h2>" in repaired, "h2 opener not repaired"
    assert "<p>" in repaired, "p opener not repaired"
    assert "<div class=" in repaired, "div opener not repaired"
    # Closing tags already had ``/`` — must still have ``</``.
    assert "</h1>" in repaired, "h1 closer not preserved"
    assert "</h2>" in repaired, "h2 closer not preserved"
    assert "</p>" in repaired, "p closer not preserved"
    assert "</div>" in repaired, "div closer not preserved"
    assert "</body>" in repaired, "body closer not preserved"
    assert "</html>" in repaired, "html closer not preserved"


# ---------------------------------------------------------------------------
# BUG-R134: valid_llm_html_report must reject reports with bare tag openers
# ---------------------------------------------------------------------------

def test_valid_llm_html_report_rejects_broken_html():
    """BUG-R134 (2026-09-14): valid_llm_html_report only checked doctype and
    </html>, missing the case where the LLM drops '<' from tags. A report
    with `div class="x">` instead of `<div class="x">` was accepted as valid
    even though browsers would render it as raw source text.

    The fix: strip <style> blocks (they contain tag selectors), then look for
    tag patterns missing '<' prefix in the remaining HTML.
    """
    import tempfile
    from agents.react_agent import valid_llm_html_report

    # Build a report with multiple bare tag openers (mimicking LLM output).
    broken_html = """<!DOCTYPE html>
<html>
<head>
    <title>Test</title>
    <style>
        body { background: #fff; }
        h1, h2 { color: #000; }
        div.container { padding: 20px; }
    </style>
</head>
<body>
    div class="header">
        h1>Incident Report
        p>Some text
    /div>
    div class="section">
        p>More text with span class="cite">source: foo/span>
    /div>
</body>
</html>"""

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".html", delete=False, encoding="utf-8"
    ) as f:
        f.write(broken_html)
        tmp_path = f.name

    assert valid_llm_html_report(tmp_path) is False, (
        "valid_llm_html_report must reject reports with bare tag openers "
        "(missing '<' prefix) that browsers would render as raw text."
    )


def test_valid_llm_html_report_accepts_well_formed_html():
    """BUG-R134 follow-up: valid_llm_html_report must still accept well-formed
    HTML after the new broken-tag detection is added.
    """
    import tempfile
    from agents.react_agent import valid_llm_html_report

    well_formed = """<!DOCTYPE html>
<html>
<head>
    <title>Test</title>
    <style>
        body { background: #fff; }
        h1, h2 { color: #000; }
        div.container { padding: 20px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Incident Report</h1>
        <p>Some text</p>
    </div>
    <div class="section">
        <p>More text with <span class="cite">source: foo</span></p>
    </div>
</body>
</html>"""

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".html", delete=False, encoding="utf-8"
    ) as f:
        f.write(well_formed)
        tmp_path = f.name

    assert valid_llm_html_report(tmp_path) is True, (
        "valid_llm_html_report should accept well-formed HTML reports."
    )


# ---------------------------------------------------------------------------
# BUG-R135: Cloudflare HTTP 400 fallback to coarser aggInterval
# ---------------------------------------------------------------------------

def test_cloudflare_400_fallback_coarser_agginterval(monkeypatch):
    """BUG-R135 (2026-09-14): When Cloudflare Radar returns HTTP 400 because
    the aggInterval is too granular for the date range, the old code raised
    immediately. The fix tries coarser intervals (15m → 1h → 1d) before
    giving up.
    """
    from detectors.traffic import traffic_detector as td

    class FakeResp:
        def __init__(self, status, json_data=None, text=""):
            self.status_code = status
            self._json = json_data
            self.text = text
        def json(self):
            return self._json or {}

    class FakeSession:
        def __init__(self):
            self.calls = []
            # Sequence: 400 (aggInterval too small), 200 with coarser 1h
            self.responses = [
                FakeResp(400, {"errors": [{"message": "aggInterval too small"}]}),
                FakeResp(200, {
                    "success": True,
                    "result": {
                        "timestamps": ["2025-01-01T00:00:00Z"],
                        "values": [1.0],
                    }
                }),
            ]
        def get(self, url, params=None, timeout=None):
            self.calls.append((url, params))
            return self.responses[len(self.calls) - 1]

    class FakeApi:
        pass
    api = FakeApi()
    api.base_url = "https://api.cloudflare.com/..."
    api.session = FakeSession()

    params = {
        "dateStart": "2025-01-01T00:00:00Z",
        "dateEnd": "2025-01-02T00:00:00Z",
        "asn": 16509,
        "format": "json",
        "aggInterval": "15m",
        "location": "US",
    }

    ts, vals = td._request_with_location(api, params, asn=16509)

    # Should have made 2 calls: initial 400, then 200 with coarser interval
    assert len(api.session.calls) == 2, f"Expected 2 calls, got {len(api.session.calls)}"
    # First call: aggInterval=15m, location=US
    assert api.session.calls[0][1]["aggInterval"] == "15m"
    assert api.session.calls[0][1].get("location") == "US"
    # Second call: should have coarser interval (1h) and no location
    assert api.session.calls[1][1]["aggInterval"] == "1h"
    assert "location" not in api.session.calls[1][1]
    assert ts == ["2025-01-01T00:00:00Z"]
    assert vals == [1.0]


def test_cloudflare_400_fallback_to_1d_after_two_smaller_failures(monkeypatch):
    """BUG-R135: When even 1h aggInterval fails, the fix escalates to 1d.
    """
    from detectors.traffic import traffic_detector as td

    class FakeResp:
        def __init__(self, status, json_data=None, text=""):
            self.status_code = status
            self._json = json_data
            self.text = text
        def json(self):
            return self._json or {}

    class FakeSession:
        def __init__(self):
            self.calls = []
            # Sequence: 400 → 400 (1h also fails) → 200 (1d succeeds)
            self.responses = [
                FakeResp(400, {"errors": [{"message": "aggInterval too small"}]}),
                FakeResp(400, {"errors": [{"message": "still too small"}]}),
                FakeResp(200, {
                    "success": True,
                    "result": {
                        "timestamps": ["2025-01-01T00:00:00Z"],
                        "values": [1.0],
                    }
                }),
            ]
        def get(self, url, params=None, timeout=None):
            self.calls.append((url, params))
            return self.responses[len(self.calls) - 1]

    class FakeApi:
        pass
    api = FakeApi()
    api.base_url = "https://api.cloudflare.com/..."
    api.session = FakeSession()

    params = {
        "dateStart": "2025-01-01T00:00:00Z",
        "dateEnd": "2025-01-02T00:00:00Z",
        "asn": 16509,
        "format": "json",
        "aggInterval": "15m",
        "location": "US",
    }

    ts, vals = td._request_with_location(api, params, asn=16509)

    assert len(api.session.calls) == 3, f"Expected 3 calls, got {len(api.session.calls)}"
    # 2nd call: 1h coarser
    assert api.session.calls[1][1]["aggInterval"] == "1h"
    assert "location" not in api.session.calls[1][1]
    # 3rd call: 1d even coarser
    assert api.session.calls[2][1]["aggInterval"] == "1d"
    assert "location" not in api.session.calls[2][1]
    assert ts == ["2025-01-01T00:00:00Z"]
    assert vals == [1.0]
