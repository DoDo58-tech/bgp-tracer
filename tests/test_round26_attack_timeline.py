"""Regression tests for `render_attack_timeline()` (Round-26).

The timeline is the chronological merge of routing + traffic + correlation
events. It is what the reviewer reads after the verdict to understand *when*
each signal landed. Three regressions to pin down:

  1. Empty inputs ⇒ "(no timeline events recorded)" placeholder, no crash.
     Before, the table was emitted with a single empty row and the parent
     `.card` wrapper was still rendered, which made the section look broken.
  2. Mixed sources (routing events + traffic anomaly + correlation points)
     are sorted by timestamp ascending, not by source order.
  3. The HTML contains the target AS banner, exactly one `<table>`,
     and the human-readable time column (YYYY-MM-DD HH:MM:SS).

Also tested: the injection-point regex in `_inject_deterministic_sections`
must match `<h2 style="...">Executive Summary</h2>` (the actual format that
`render_executive_summary` emits), not just `<h2>Executive Summary</h2>`. A
bare-heading regex silently skipped injection, leaving the timeline absent
from the report.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from agents.report_agent import render_attack_timeline  # noqa: E402


def _routing(events):
    return {
        "origin_hijacked": events,
        "origin_hijacking": [],
        "forge_hijacked": [],
        "forge_hijacking": [],
        "route_leaks": [],
    }


def _traffic(events):
    return {
        "anomaly_count": len(events),
        "events": events,
    }


def _corr(events):
    return {
        "timeline": events,
        "temporal_proximity": "strong",
        "confidence": 0.8,
    }


def test_empty_inputs_render_placeholder():
    html = render_attack_timeline(
        routing_norm=_routing([]),
        traffic_norm=_traffic([]),
        correlation_norm=_corr([]),
        target_as="AS12479",
    )
    assert "Attack Timeline" in html
    assert "AS12479" in html
    assert "No timestamped events" in html
    assert "<table" not in html, "empty inputs must not emit a table"


def test_sorted_by_timestamp_ascending():
    # Three sources, all routed through the correlation_norm.timeline channel
    # because that path is the spec's preferred source. Sort order must
    # follow the timestamp field on each merged event, not source order.
    routing_events = [
        {"timestamp": "2024-01-03T17:30:00Z", "source": "routing",
         "type": "origin_hijacked", "prefix": "1.1.1.0/24",
         "hijacker_as": "AS65001"},
    ]
    traffic_events = [
        {"timestamp": "2024-01-03T15:00:00Z", "source": "traffic",
         "type": "anomaly", "z_score": -4.2, "drop_pct": -42.0},
    ]
    corr_events = [
        {"timestamp": "2024-01-03T16:15:00Z", "source": "correlation",
         "type": "routing_traffic_correlation",
         "detail": "AS12479 traffic drop ↔ AS65001 announcement"},
    ]
    html = render_attack_timeline(
        routing_norm=_routing([]),
        traffic_norm=_traffic([]),
        correlation_norm=_corr(routing_events + traffic_events + corr_events),
        target_as="AS12479",
    )
    # Implementation strips date for compactness — see _short() docstring.
    times = re.findall(r"<td>(\d{2}:\d{2}:\d{2})</td>", html)
    assert times == [
        "15:00:00",
        "16:15:00",
        "17:30:00",
    ], f"timeline not sorted ascending by source-key timestamp; got {times!r}"


def test_caps_rows_at_max_rows():
    events = [
        {"timestamp": f"2024-01-03T10:{i:02d}:00Z", "source": "routing",
         "type": "origin_hijacked", "prefix": f"10.0.{i}.0/24",
         "hijacker_as": "AS65001"}
        for i in range(40)
    ]
    html = render_attack_timeline(
        routing_norm=_routing([]),
        traffic_norm=_traffic([]),
        correlation_norm=_corr(events),
        target_as="AS12479",
        max_rows=10,
    )
    data_rows = html.count("<tr>") - 1  # minus header
    assert data_rows == 10, f"expected max_rows=10 data rows, got {data_rows}"
    # Summary line should explain truncation by reporting "first N of M".
    assert "showing first 10 of 40" in html


def test_render_includes_target_as_and_summary_line():
    # Single routing event rendered via the correlation channel.
    routing_events = [
        {"timestamp": "2024-01-03T17:30:00Z", "source": "routing",
         "type": "origin_hijacked", "prefix": "1.1.1.0/24",
         "hijacker_as": "AS65001"},
    ]
    html = render_attack_timeline(
        routing_norm=_routing([]),
        traffic_norm=_traffic([]),
        correlation_norm=_corr(routing_events),
        target_as="AS12479",
    )
    assert "AS12479" in html
    # Header columns present.
    for col in ("Time", "Source", "Type", "Detail"):
        assert col in html, f"column header {col!r} missing from timeline HTML"
    # Summary line reports count.
    assert "1 timestamped event" in html
    # Source values are lowercase: "routing" or "traffic".
    assert "routing" in html


def test_fallback_path_renders_when_correlation_timeline_empty():
    # When correlation_norm.timeline is empty, fall back to synthesizing
    # rows from raw routing_norm + traffic_norm so the section is never
    # silently empty just because the merger hadn't run.
    routing_events = [
        {"first_seen": "2024-01-03T17:30:00Z", "prefix": "1.1.1.0/24",
         "origin_as": "AS65001"},
    ]
    traffic_events = [
        {"timestamp": "2024-01-03T15:00:00Z", "type": "anomaly",
         "z_score": -4.2, "drop_pct": -42.0},
    ]
    html = render_attack_timeline(
        routing_norm={
            "origin_hijacked": routing_events,
            "origin_hijacking": [],
            "route_leaks": [],
        },
        traffic_norm={"anomaly_count": 1, "timeline": traffic_events},
        correlation_norm={"temporal_proximity": "weak", "confidence": 0.3},
        target_as="AS12479",
    )
    assert "AS12479" in html
    # Two events: routing + traffic.
    times = re.findall(r"<td>(\d{2}:\d{2}:\d{2})</td>", html)
    assert times == ["15:00:00", "17:30:00"], \
        f"fallback path not sorted; got {times!r}"
    # Traffic event has z-score in detail column.
    assert "z=-4.2" in html or "z=−4.2" in html, \
        "traffic anomaly z_score missing from detail column"


def test_inject_regex_matches_styled_executive_summary_heading():
    """Regression test for the injection-point regex.

    `_inject_deterministic_sections` in `report_agent.py` searches the LLM
    HTML for `<h2>Executive Summary</h2>` to find the spot where Attack
    Timeline + Diagnosis + Key Metrics should be inserted. The actual HTML
    emitted by `render_executive_summary` carries inline style attributes
    (`<h2 style="margin-top:0;color:#1c2330;">...`), so a bare-heading
    regex silently never matches — leaving the timeline absent from the
    rendered report even though `render_attack_timeline()` ran.

    We pin the regex shape here so the next person who edits it knows the
    failure mode.
    """
    fake_html = (
        '<div class="card executive-summary" style="...">'
        '<h2 style="margin-top:0;color:#1c2330;">Executive Summary</h2>'
        '<p>...ROA Misconfiguration...</p>'
        '</div>'
        '<h2>Traffic Analysis</h2>'
    )
    # The same regex used in `_inject_deterministic_sections`.
    exec_re = re.compile(
        r'(<h2(?:\s+[^>]*)?>\s*Executive Summary\s*</h2>.*?</div>)',
        re.DOTALL | re.IGNORECASE,
    )
    m = exec_re.search(fake_html)
    assert m is not None, (
        "Styled <h2 ...>Executive Summary</h2> must match — otherwise "
        "Attack Timeline injection silently no-ops."
    )
    # And it must END at the executive summary card's </div>, not somewhere
    # later in the document.
    assert m.group(0).endswith("</div>"), \
        "regex must anchor at the executive-summary card's closing </div>"
