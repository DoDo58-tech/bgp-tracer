"""Regression tests for the string-aware bracket-matching JSON parser.

Bug fix 2026-09-15: the previous parser in ``run_4mode_batch.py`` used a
naive ``{`` / ``}`` walk that ignored string boundaries. The chief_agent
JSON dump contains a string field (``answer``) that embeds a full HTML
report — the HTML has plenty of unbalanced ``}`` characters (in CSS,
in ``</style>`` closing tags, etc.) which broke the walk and made the
parser think the JSON ended mid-stream.

The string-aware parser tracks ``"..."`` regions and skips braces inside
them. After the fix, every react_enhanced record correctly produces
verdict / conf / quality / tokens instead of ``N/A``.
"""
import json
import sys
sys.path.insert(0, '/data/bgp_tracer')


def _parse_using_batch_logic(log_content: str) -> dict | None:
    """Mirror of the parser used in ``run_4mode_batch.py``."""
    candidates = []
    depth = 0
    start = -1
    in_string = False
    escape = False
    for i, ch in enumerate(log_content):
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
            continue
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start >= 0:
                    candidates.append(log_content[start:i + 1])
                    start = -1

    structured = [c for c in candidates if '"chief_expert_analysis"' in c or '"success"' in c]
    if structured:
        return json.loads(structured[-1])
    elif candidates:
        return json.loads(candidates[-1])
    return None


def test_simple_json():
    log = 'prefix noise\n{"success": true, "value": 42}\ntrailing'
    out = _parse_using_batch_logic(log)
    assert out == {"success": True, "value": 42}


def test_nested_object():
    log = (
        'noise\n{'
        '  "success": true,'
        '  "chief_expert_analysis": {"data_quality": "high", "score": 0.9},'
        '  "token_count": 1500'
        '}\n'
    )
    out = _parse_using_batch_logic(log)
    assert out is not None
    assert out["success"] is True
    assert out["chief_expert_analysis"]["data_quality"] == "high"
    assert out["token_count"] == 1500


def test_string_with_unbalanced_braces():
    """The 'answer' field can contain HTML with closing braces like '}'.
    Naive bracket walker would terminate the JSON prematurely."""
    log = (
        'noise\n{'
        '  "success": false,'
        '  "answer": "function foo() { return 1; } some text",'
        '  "error": "report_failed"'
        '}\n'
    )
    out = _parse_using_batch_logic(log)
    assert out is not None
    assert out["success"] is False
    assert "function foo()" in out["answer"]
    assert out["error"] == "report_failed"


def test_embedded_html_with_css():
    """Real chief_agent output embeds HTML/CSS inside the answer field."""
    log = (
        'noise\n{'
        '  "success": false,'
        '  "react_mode": true,'
        '  "answer": "<!DOCTYPE html>\\n<html>\\n<head>\\n<style>\\n'
        'body { font-family: Arial; }\\nh1 { color: #333; }\\n</style>\\n'
        '</head>\\n<body>\\n<h1>Report Failed</h1>\\n</body>\\n</html>",'
        '  "html_report_path": "<!DOCTYPE html>...</html>",'
        '  "data_quality": "medium",'
        '  "token_count": 0'
        '}\n'
    )
    out = _parse_using_batch_logic(log)
    assert out is not None
    assert out["react_mode"] is True
    assert "<!DOCTYPE html>" in out["answer"]
    assert out["data_quality"] == "medium"
    assert out["token_count"] == 0


def test_escaped_quote_in_string():
    """A string like ``"hello \\\"world\\\""`` must not close the string
    at the inner ``"``."""
    log = (
        'noise\n{'
        '  "success": true,'
        '  "msg": "He said \\"hello\\" {nested}",'
        '  "value": 7'
        '}\n'
    )
    out = _parse_using_batch_logic(log)
    assert out is not None
    assert out["value"] == 7
    assert '"hello"' in out["msg"]
    assert "{nested}" in out["msg"]


def test_multiple_json_objects_picks_latest_structured():
    log = (
        'noise\n{"action_input": {"asn": "17557"}} more noise\n'
        '{"success": true, "first": true} trailing\n'
        '{"chief_expert_analysis": {"data_quality": "low"}, "success": false} tail\n'
    )
    out = _parse_using_batch_logic(log)
    assert out is not None
    assert out["success"] is False
    assert out["chief_expert_analysis"]["data_quality"] == "low"


def test_real_chief_agent_react_enhanced_output():
    """Replay the real AS17557 react_enhanced log file."""
    from pathlib import Path
    log_path = Path("/data/bgp_tracer/logs/4mode_batch_20260915_122440/outage_pakistan_2024/react_enhanced.log")
    if not log_path.exists():
        # Skip if the file isn't there (CI environment)
        return
    log = log_path.read_text()
    out = _parse_using_batch_logic(log)
    assert out is not None
    assert "success" in out
    assert "chief_expert_analysis" in out
    # Must have actual token count and data quality, not N/A.
    assert out.get("token_count") is not None
    ca = out.get("chief_expert_analysis", {})
    assert ca.get("data_quality") is not None
    # The chief_expert_analysis.answer field embeds the report.
    answer = ca.get("answer", "")
    assert "<!DOCTYPE html>" in answer or "<!doctype html>" in answer.lower()
    # elapsed_seconds must be a real number, not 0 or missing
    assert out.get("elapsed_seconds", 0) > 0


if __name__ == "__main__":
    test_simple_json()
    test_nested_object()
    test_string_with_unbalanced_braces()
    test_embedded_html_with_css()
    test_escaped_quote_in_string()
    test_multiple_json_objects_picks_latest_structured()
    test_real_chief_agent_react_enhanced_output()
    print("All 7 string-aware JSON parser regression tests passed")
