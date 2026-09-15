"""Regression tests for the JSON-key placeholder scrubber.

Bug fix 2026-09-15: the LLM frequently emitted JSON keys like
``[target_as]`` or ``[user_analysis_window]`` as visible text in the
report. We added ``_scrub_json_key_placeholders`` to substitute these
with the actual values so the operator never sees raw JSON field names
in the final HTML.
"""
import sys
sys.path.insert(0, '/data/bgp_tracer')

from agents.report_agent import _scrub_json_key_placeholders


def test_scrub_target_as_with_bare_number():
    html = 'h1>Report for [target_as]/h1>'
    out = _scrub_json_key_placeholders(html, asn="22773", start_time="X", end_time="Y")
    assert "[target_as]" not in out
    assert "22773" in out
    assert "AS" not in out  # raw value, not prefixed


def test_scrub_target_as_with_as_prefix():
    html = 'h1>Report for [target_as]/h1>'
    out = _scrub_json_key_placeholders(html, asn="AS22773", start_time="X", end_time="Y")
    assert "[target_as]" not in out
    assert "AS22773" in out


def test_scrub_user_analysis_window():
    html = 'p>Window: [user_analysis_window]/p>'
    out = _scrub_json_key_placeholders(
        html,
        asn="22773",
        start_time="2025-05-01 16:45",
        end_time="2025-05-01 20:00",
    )
    assert "[user_analysis_window]" not in out
    assert "2025-05-01 16:45 to 2025-05-01 20:00" in out


def test_scrub_unknown_placeholder_replaced_with_no_data():
    html = 'p>events: [some.unknown.field]/p>'
    out = _scrub_json_key_placeholders(html, asn="22773", start_time="X", end_time="Y")
    assert "[some.unknown.field]" not in out
    assert "(no data)" in out


def test_scrub_empty_string_handled():
    html = 'p>window: [user_analysis_window]/p>'
    out = _scrub_json_key_placeholders(html, asn="", start_time="", end_time="")
    assert "[user_analysis_window]" not in out
    assert "(no data)" in out


def test_scrub_does_not_touch_markdown_citations():
    """Citations use [source: field] format which has a colon and must not
    be touched."""
    html = 'p>As cited in [source: traffic_anomaly_count] the count was 3/p>'
    out = _scrub_json_key_placeholders(html, asn="X", start_time="A", end_time="B")
    assert "[source: traffic_anomaly_count]" in out


def test_scrub_does_not_touch_well_formed_html():
    """The scrubber must not break valid HTML that happens to contain brackets."""
    html = (
        '<!DOCTYPE html><html><head><title>Test</title></head>'
        '<body><h1>Hello</h1><p>No placeholders here.</p></body></html>'
    )
    out = _scrub_json_key_placeholders(html, asn="X", start_time="A", end_time="B")
    assert out == html


def test_scrub_handles_multiple_placeholders():
    html = (
        'h1>AS [target_as] window [user_analysis_window] events [unknown.field]/h1>'
    )
    out = _scrub_json_key_placeholders(
        html,
        asn="17557",
        start_time="2024-07-31 08:30",
        end_time="2024-07-31 10:30",
    )
    assert "[target_as]" not in out
    assert "[user_analysis_window]" not in out
    assert "[unknown.field]" not in out
    assert "17557" in out
    assert "2024-07-31 08:30 to 2024-07-31 10:30" in out
    assert "(no data)" in out


if __name__ == "__main__":
    test_scrub_target_as_with_bare_number()
    test_scrub_target_as_with_as_prefix()
    test_scrub_user_analysis_window()
    test_scrub_unknown_placeholder_replaced_with_no_data()
    test_scrub_empty_string_handled()
    test_scrub_does_not_touch_markdown_citations()
    test_scrub_does_not_touch_well_formed_html()
    test_scrub_handles_multiple_placeholders()
    print("All 8 placeholder-scrub regression tests passed")
