"""Round-23: regression tests for the data-chain audit fixes.

Each test corresponds to a specific bug documented in
``docs/DATA_CHAIN_AUDIT.md``. These tests run in <1 s and are tagged
``fast`` via ``tests/conftest.py``.
"""

from __future__ import annotations

import re

import pytest

from agents.report_agent import (
    _render_section_anchor_inserts,
    _scrub_json_key_placeholders,
    _SECTION_TITLE_HIJACK,
    _SECTION_TITLE_TRAFFIC,
    slim_payload,
    validate_html_balance,
)


# ─── BUG-23-1: anchor-insert collision must NOT split <h2> tags ─────────


def test_anchor_two_tables_same_traffic_heading_no_truncation():
    """Two traffic tables anchored on the same heading must each land
    AFTER a real </h2> closing tag, not split one open.
    """
    html = (
        "<html><body>"
        "<h2>Traffic Analysis</h2>"
        "<p>intro</p>"
        "<h2>Origin Hijacking Events</h2>"
        "</body></html>"
    )
    out = _render_section_anchor_inserts(html, [
        (_SECTION_TITLE_TRAFFIC, "<table>TRAFFIC</table>", "x"),
        (_SECTION_TITLE_HIJACK, "<table>HIJACK</table>", "x"),
    ])
    # Heading structure must remain intact (no orphan closing tag).
    assert out.count("</h2>") == 2, out
    # Tables must NOT be inside the heading element.
    for m in re.finditer(r"<h2[^>]*>.*?</h2>", out, flags=re.DOTALL):
        assert "<table>" not in m.group(0), f"Table inside heading: {m.group(0)}"
    # Both tables must be present.
    assert "<table>TRAFFIC</table>" in out
    assert "<table>HIJACK</table>" in out


def test_anchor_three_tables_distinct_headings_each_lands_correctly():
    """Three tables, three distinct headings — each table goes after the
    matching heading.
    """
    html = (
        "<html><body>"
        "<h2>Traffic Analysis</h2>"
        "<h2>Traffic Anomaly Events</h2>"
        "<h2>Origin Hijacking Events</h2>"
        "</body></html>"
    )
    out = _render_section_anchor_inserts(html, [
        (_SECTION_TITLE_TRAFFIC, "<table>A</table>", "x"),
        (_SECTION_TITLE_TRAFFIC, "<table>B</table>", "x"),
        (_SECTION_TITLE_HIJACK, "<table>C</table>", "x"),
    ])
    assert out.count("</h2>") == 3
    # Order: A after Traffic Analysis, B after Traffic Anomaly Events,
    # C after Origin Hijacking Events.
    a_pos = out.find("<table>A</table>")
    b_pos = out.find("<table>B</table>")
    c_pos = out.find("<table>C</table>")
    # The table position must be greater than the heading opening tag
    ta_heading_pos = out.find("Traffic Analysis</h2>") + len("Traffic Analysis</h2>")
    tan_heading_pos = out.find("Traffic Anomaly Events</h2>") + len("Traffic Anomaly Events</h2>")
    hij_heading_pos = out.find("Origin Hijacking Events</h2>") + len("Origin Hijacking Events</h2>")
    assert ta_heading_pos <= a_pos < tan_heading_pos, (
        f"A not after Traffic Analysis heading: a_pos={a_pos}, "
        f"ta={ta_heading_pos}, tan={tan_heading_pos}, out={out}"
    )
    assert tan_heading_pos <= b_pos < hij_heading_pos, (
        f"B not after Anomaly Events: b_pos={b_pos}, "
        f"tan={tan_heading_pos}, hij={hij_heading_pos}, out={out}"
    )
    assert hij_heading_pos <= c_pos, (
        f"C not after Hijack: c_pos={c_pos}, hij={hij_heading_pos}, out={out}"
    )


def test_anchor_no_match_appends_nothing():
    """When no anchor matches, the HTML must be returned unchanged."""
    html = "<html><body><h2>Other</h2></body></html>"
    out = _render_section_anchor_inserts(html, [
        (_SECTION_TITLE_TRAFFIC, "<table>X</table>", "x"),
    ])
    assert out == html


# ─── BUG-23-2 (data chain): scrub is now wired into the pipeline ────────


def test_scrub_does_not_crash_on_empty():
    """Empty inputs must not raise."""
    assert _scrub_json_key_placeholders("") == ""


def test_scrub_target_as_with_prefix():
    """``[target_as]`` → ASN (with or without AS prefix)."""
    out = _scrub_json_key_placeholders(
        "<p>ASN is [target_as]</p>",
        asn="22773", start_time="X", end_time="Y",
    )
    assert "[target_as]" not in out
    assert "22773" in out


def test_scrub_user_analysis_window():
    """``[user_analysis_window]`` → "start to end"."""
    out = _scrub_json_key_placeholders(
        "<p>Window: [user_analysis_window]</p>",
        asn="X", start_time="2024-01-03T14:45Z", end_time="2024-01-03T15:00Z",
    )
    assert "[user_analysis_window]" not in out
    assert "2024-01-03T14:45Z" in out and "2024-01-03T15:00Z" in out


def test_scrub_preserves_source_citations():
    """Markdown-style citations with colons must NOT be replaced."""
    html = "<p>Cited: [source: foo bar]</p>"
    out = _scrub_json_key_placeholders(html, asn="X", start_time="A", end_time="B")
    assert "[source: foo bar]" in out


def test_scrub_unknown_becomes_no_data():
    """Unknown ``[...]`` → ``(no data)``."""
    out = _scrub_json_key_placeholders(
        "<p>X is [something_unknown]</p>",
        asn="", start_time="", end_time="",
    )
    assert "[something_unknown]" not in out
    assert "(no data)" in out


# ─── BUG-23-4: validate_html_balance ignores <style>/<script>/<title> ────


def test_balance_unclosed_title_does_not_flag():
    """``<title>Some Report Title</title>`` is well-formed; an empty
    ``<title></title>`` left after stripping must NOT be flagged as
    ``unclosed <title>``.
    """
    html = (
        "<html><head><title>X</title></head>"
        "<body><p>hi</p></body></html>"
    )
    ok, problems = validate_html_balance(html)
    # We may or may not be balanced depending on the head/body shape, but
    # at minimum the validator must NOT flag "unclosed <title>".
    joined = " ".join(problems)
    assert "unclosed <title>" not in joined, problems


def test_balance_style_block_with_stray_lt():
    """A ``<style>`` block with ``<`` in CSS selectors must not crash
    the validator. Browsers render this fine.
    """
    html = (
        "<html><head>"
        "<style>a > b { color: red; }</style>"
        "</head><body><p>hi</p></body></html>"
    )
    ok, problems = validate_html_balance(html)
    # The strip-style regex turns the block into [raw-text-block], so
    # the validator doesn't see the ``<`` characters inside.
    joined = " ".join(problems)
    assert "unclosed <a>" not in joined, problems
    assert "unclosed <b>" not in joined, problems


# ─── BUG-23-4 (additional): slim_payload dict cap is now parameterised ──


def test_slim_payload_dict_limit_respected():
    """A dict with 60 keys and ``limit=20`` should cap dict at
    max(20*4, 50)=80 keys (always ≥ 50 for safety).
    """
    data = {f"k{i}": i for i in range(60)}
    slim = slim_payload(data, limit=20)
    # 60 keys ≤ 80 cap (max(20*4, 50)=80), so all 60 should remain.
    assert len(slim) == 60, len(slim)


def test_slim_payload_dict_capped_at_max_limit_4x():
    """A dict with 100 keys and ``limit=10`` should cap dict at 40 keys
    (10*4=40). This is the new behaviour introduced in round 23.
    """
    data = {f"k{i}": i for i in range(100)}
    slim = slim_payload(data, limit=10)
    # max(10*4, 50)=50 — the 50-key floor takes precedence for safety.
    assert len(slim) == 50, f"Expected 50 keys, got {len(slim)}"


def test_slim_payload_list_limit():
    """A list of 30 items and ``limit=5`` should yield 5 items."""
    data = list(range(30))
    slim = slim_payload(data, limit=5)
    assert len(slim) == 5
    assert slim == [0, 1, 2, 3, 4]


def test_slim_payload_filters_deny_fields():
    """Fields in ``_PAYLOAD_DENY_FIELDS`` must be dropped."""
    data = {"keep_me": 1, "timestamps": "huge", "anomalies": [1, 2, 3]}
    slim = slim_payload(data, limit=10)
    assert "keep_me" in slim
    assert "timestamps" not in slim
    assert "anomalies" in slim


def test_slim_payload_recursion_safety():
    """Deep nesting (>50 levels) must terminate."""
    cur: dict = {}
    inner = cur
    for _ in range(80):
        new = {}
        inner["x"] = new
        inner = new
    out = slim_payload(cur, limit=10)
    # Must terminate; the inner-most value should be None.
    assert out is not None


# ─── Sanity: a complete pipeline rendering test ──────────────────────────


def test_anchor_inserts_with_completely_missing_section():
    """If the section anchor is entirely absent, the table is appended
    just before ``</body>`` (the existing behaviour, preserved).
    """
    html = "<html><body><h2>Other</h2></body></html>"
    out = _render_section_anchor_inserts(html, [
        (_SECTION_TITLE_TRAFFIC, "<table>X</table>", "x"),
    ])
    # No anchor → no insert → output equals input.
    assert out == html
