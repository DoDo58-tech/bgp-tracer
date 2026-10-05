"""Offline render test for the structure-locked report template.

Renders real saved analysis payloads through ``report_template.render_report``
without calling the LLM, so template/structure defects surface even when the
LLM gateway is down. Also exercises the LLM-narrative parser with synthetic
responses to verify the JSON contract and its fallbacks.

Usage::

    python scripts/render_template_check.py
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agents.report_template import (  # noqa: E402
    build_table,
    parse_narrative,
    render_report,
    resolve_traffic_plot,
)

OUT = ROOT / "results" / "template_preview"
OUT.mkdir(parents=True, exist_ok=True)


# ── Fixtures mirroring the two shapes seen in production ─────────────────────

def _leak_event(ts, prefix=None, as_path=None, leaker=None):
    return {
        "timestamp": ts, "prefix": prefix, "as_path": as_path,
        "leaked_by": leaker, "severity": "high",
    }


def case_mixed() -> dict:
    """Hijack + leak + outage + traffic, i.e. every event class populated."""
    return {
        "asn": "16276",
        "start_time": "2024-10-29 13:16",
        "end_time": "2024-10-29 13:54",
        "traffic": {
            "anomaly_count": 4,
            "anomalies": [
                {"timestamp": "2024-10-29T13:30:00Z", "current_value": 0.756,
                 "severity": "critical", "z_score": -8.2, "baseline_method": "weekly"},
                {"timestamp": "2024-10-29T13:45:00Z", "current_value": 0.721,
                 "severity": "critical", "z_score": -8.9, "baseline_method": "weekly"},
                {"timestamp": "2024-10-29T14:10:00Z", "current_value": 2.4e9,
                 "severity": "critical", "z_score": 9.1},
                {"timestamp": "2024-10-29T14:30:00Z", "current_value": 0.79,
                 "severity": "high", "change_type": "sudden_drop"},
            ],
            "peak_trough_drop_pct": 99.99,
            "percent_change": -30.51,
            "max_severity": "critical",
            "traffic_anomaly_window": {"start": "2024-10-29 13:30", "end": "2024-10-29 14:30"},
        },
        "routing": {
            "origin_hijacked": [
                {"timestamp": "2024-10-29T13:16:00Z", "prefix": "45.15.177.0/24",
                 "victim_as": "16276", "origin_as": "208796", "as_path": "208796 3356 16276"},
                {"timestamp": "2024-10-29T13:22:00Z", "prefix": "2a0a:e805:210::/44",
                 "victim_as": "16276", "origin_as": "202365"},
            ],
            "origin_hijacking": [
                {"timestamp": "2024-10-29T13:25:00Z", "prefix": "104.156.151.0/24",
                 "origin_as": "16276", "victim_as": "197715"},
            ],
            "route_leaks": [
                # Informative leak: prefix + path present.
                _leak_event("2024-10-29T13:18:06Z", "91.242.162.0/24", "16276 3356 15169"),
                # Detergent leak: neither prefix nor path (the production defect).
                _leak_event("2024-10-29T13:19:29Z"),
                _leak_event("2024-10-29T13:20:11Z"),
            ],
            "outage_analysis": {"is_outage_suspected": True, "outage_score": 0.30},
        },
        "correlation": {
            "correlation": {
                "level": "high", "strength": 0.80, "temporal_proximity": "weak",
                "delta_ts": [
                    {"routing_ts": "2024-10-29T13:16:00", "traffic_ts": "2024-10-29T13:30:00",
                     "delta_hours": 0.23, "direction": "below", "window": "within 2h"},
                ],
            }
        },
    }


def case_traffic_only() -> dict:
    """No routing events at all — sections for those classes must vanish."""
    return {
        "asn": "24940",
        "start_time": "2026-08-29 10:33",
        "end_time": "2026-08-29 16:33",
        "traffic": {
            "anomaly_count": 2,
            "anomalies": [
                {"timestamp": "2026-08-29T11:00:00Z", "current_value": 12.5,
                 "severity": "high", "deviation": -4.4},
            ],
            "peak_trough_drop_pct": 62.0,
            "percent_change": -12.0,
            "max_severity": "high",
        },
        "routing": {},
        "correlation": {"correlation": {"level": "low", "strength": 0.12,
                                        "temporal_proximity": "none"}},
    }


def case_empty() -> dict:
    """Nothing detected anywhere — must still produce a complete document."""
    return {
        "asn": "13335",
        "start_time": "2025-01-01 00:00",
        "end_time": "2025-01-01 01:00",
        "traffic": {"anomaly_count": 0, "anomalies": []},
        "routing": {},
        "correlation": {},
    }


def render(name: str, case: dict) -> Path:
    html = render_report(
        asn=case["asn"],
        start_time=case["start_time"],
        end_time=case["end_time"],
        traffic_result=case["traffic"],
        routing_result=case["routing"],
        correlation_analysis=case["correlation"],
        org_name=None,
        narrative={},
        narrative_source="python-fallback",
    )
    path = OUT / f"{name}_AS{case['asn']}.html"
    path.write_text(html, encoding="utf-8")
    return path


def check(name: str, case: dict) -> list:
    """Render and assert the structural invariants we care about."""
    path = render(name, case)
    html = path.read_text(encoding="utf-8")
    issues: list = []

    # 1. Exactly ONE absolute width authority.
    #    The width-tearing defect was caused by two competing ABSOLUTE widths
    #    (LLM `body{max-width:1100px}` vs injected
    #    `.report-container{max-width:1180px}`). A relative `max-width:100%`
    #    on a descendant cannot conflict — it just tracks its parent — so only
    #    absolute units are treated as a width authority here.
    import re as _re
    head = html.split("</style>")[0]
    absolute = []
    for m in _re.finditer(r"([^{}]+)\{([^{}]*)\}", head):
        selector, body = m.group(1), m.group(2)
        for w in _re.findall(r"max-width\s*:\s*([^;}]+)", body):
            if w.strip() in ("100%", "none"):
                continue  # relative to the parent ⇒ cannot conflict
            if _re.search(r"\d", w):  # a length ⇒ an absolute width authority
                sel = selector.strip().splitlines()[-1].strip()
                absolute.append((re.sub(r"\s+", " ", sel), w.strip()))
    if not any(sel == ".report" for sel, _ in absolute):
        issues.append("no max-width on the .report container")
    for sel, w in absolute:
        if sel != ".report":
            issues.append(
                f"competing absolute width on {sel!r} (max-width: {w}) — "
                f"this is the width-tearing signature"
            )

    # 2. No unrendered Jinja delimiters.
    for token in ("{{", "{%", "}}", "%}"):
        if token in html:
            issues.append(f"unrendered template token {token!r} in output")

    # 3. No raw "<table" without our wrapper class; no stray colspan mismatch.
    if "<table" in html and 'class="data"' not in html:
        issues.append("table present without the locked `data` class")

    # 4. Structural completeness: every case must keep the same section set
    #    for the sections that are always present.
    for required in ("Executive Summary", "Key Metrics", "Traffic Analysis",
                     "Routing Security", "Correlation Assessment",
                     "Evidence Chain", "Gaps"):
        if required not in html:
            issues.append(f"missing always-on section: {required}")

    # 5. Conditional sections appear only with data.
    has_hijack = bool(case["routing"].get("origin_hijacked") or case["routing"].get("origin_hijacking"))
    has_leak = bool(case["routing"].get("route_leaks"))
    if has_hijack and "Origin hijacking" not in html:
        issues.append("hijack data present but no hijack block rendered")
    if not has_hijack and "Origin hijacking —" in html:
        issues.append("no hijack data but a hijack block was rendered")
    if has_leak and "Route leak events" not in html:
        issues.append("leak data present but no leak block rendered")
    if not has_leak and "Route leak events" in html:
        issues.append("no leak data but a leak block was rendered")

    # 6. The empty-column guarantee: every emitted table must have a
    #    header count equal to its row cell count, and the renderer must not
    #    emit a column that is placeholder-only across all source rows.
    if has_leak:
        start = html.find("Route leak events")
        block = html[start:start + 6000]
        for tbl in re.finditer(r"<table class=\"data\">(.*?)</table>", block, re.S):
            ths = re.findall(r"<th>(.*?)</th>", tbl.group(1))
            body = re.search(r"<tbody>(.*?)</tbody>", tbl.group(1), re.S)
            if not body:
                continue
            for r in re.finditer(r"<tr>(.*?)</tr>", body.group(1), re.S):
                tds = re.findall(r"<td[^>]*>", r.group(1))
                if len(tds) == 1 and len(ths) > 1:
                    continue  # colspan notice row
                if len(tds) != len(ths):
                    issues.append(
                        f"leak table header/cell mismatch: {len(ths)} headers vs "
                        f"{len(tds)} cells"
                    )

    # 7. Plot: a resolved image must be a base64 <img>; otherwise an explicit
    #    gap notice — never a broken or substituted chart.
    if 'src="data:image/png;base64,' in html:
        if "Traffic Analysis" not in html.split('src="data:image/png;base64,')[0][-2000:]:
            issues.append("plot injected outside the Traffic Analysis card")
    else:
        if "No traffic plot artifact" not in html:
            issues.append("no plot and no explicit gap notice")

    return issues


def narrative_tests() -> list:
    """Verify the LLM JSON contract and its defensive parsing."""
    issues = []

    good = json.dumps({
        "executive_note": "A sustained traffic drop coincided with BGP alerts.",
        "mechanism": "Route withdrawal removed the preferred path.",
        "traffic_analysis": "The series alternated between near-zero and baseline.",
        "routing_analysis": "Several prefixes were announced by an unexpected origin.",
        "hypothesis_note": "Compare against a second collector.",
        "gap_note": "No RPKI feed was available.",
    })
    parsed = parse_narrative(good)
    if not parsed.get("executive_note", "").startswith("A sustained"):
        issues.append("clean JSON narrative failed to parse")

    fenced = f"```json\n{good}\n```"
    if parse_narrative(fenced).get("mechanism") != parsed["mechanism"]:
        issues.append("fenced JSON narrative failed to parse")

    noisy = f"Here is the analysis you asked for:\n{good}\nHope that helps!"
    if parse_narrative(noisy).get("executive_note") != parsed["executive_note"]:
        issues.append("narrative with surrounding prose failed to parse")

    # Markup must be stripped so a rogue model cannot inject tags.
    injected = json.dumps({"executive_note": "<script>alert(1)</script>Traffic dropped."})
    if "<script>" in parse_narrative(injected).get("executive_note", ""):
        issues.append("markup was not stripped from the narrative")

    # Wrong types must fall back, not crash or render junk.
    weird = json.dumps({"executive_note": {"nope": 1}, "mechanism": 42})
    out = parse_narrative(weird)
    if out.get("executive_note") or out.get("mechanism"):
        issues.append("non-string narrative values were accepted")

    # Garbage must not raise.
    for junk in ("", "not json at all", "{broken", "[]"):
        try:
            parse_narrative(junk)
        except Exception as exc:
            issues.append(f"parse_narrative raised on {junk!r}: {exc!r}")

    return issues


def table_tests() -> list:
    issues = []
    # A column that is empty in every row must be dropped.
    tbl = build_table(
        ["Timestamp", "Prefix", "Always Empty"],
        [["t1", "p1", None], ["t2", "p2", ""], ["t3", "p3", "  "]],
    )
    if tbl is None:
        issues.append("build_table dropped a table that had real data")
    elif "Always Empty" in tbl["columns"]:
        issues.append("all-empty column was not dropped")
    elif len(tbl["columns"]) != 2:
        issues.append(f"expected 2 kept columns, got {tbl['columns']}")

    # No rows at all -> None, so the caller omits the block.
    if build_table(["A", "B"], []) is not None:
        issues.append("build_table returned a table for zero rows")

    # All columns empty -> None (table carries no information).
    if build_table(["A", "B"], [[None, ""]]) is not None:
        issues.append("build_table kept a table whose every cell was empty")

    # A partially-populated column survives.
    tbl2 = build_table(["A", "B"], [[None, "x"], [None, None]])
    if not tbl2 or "B" not in tbl2["columns"] or "A" in tbl2["columns"]:
        issues.append("partially-populated column handling is wrong")

    # Column selection is decided over the FULL row list, not just the rows
    # that get displayed. A column blank in the first `row_limit` rows but
    # populated later must be kept (this is the AS17557 hijack case).
    many = [[f"t{i}", None] for i in range(120)]
    many[100][1] = "AS64496"          # only row 100 has a value
    tbl3 = build_table(["Timestamp", "Victim AS"], many, row_limit=50)
    if not tbl3 or "Victim AS" not in tbl3["columns"]:
        issues.append("column populated only beyond row_limit was wrongly dropped")
    if tbl3 and tbl3["shown"] != 50:
        issues.append(f"row_limit not honoured: showed {tbl3['shown']}")

    # A column blank across ALL rows must be dropped even past row_limit.
    allblank = [[f"t{i}", "—"] for i in range(120)]
    tbl4 = build_table(["Timestamp", "Never Set"], allblank, row_limit=50)
    if not tbl4 or "Never Set" in tbl4["columns"]:
        issues.append("all-blank column beyond row_limit was not dropped")

    return issues


def main() -> int:
    cases = [
        ("mixed", case_mixed()),
        ("traffic_only", case_traffic_only()),
        ("empty", case_empty()),
    ]
    all_issues = []
    for name, case in cases:
        issues = check(name, case)
        status = "OK" if not issues else f"{len(issues)} issue(s)"
        print(f"[{status:>12}] {name}")
        for issue in issues:
            print(f"               - {issue}")
        all_issues.extend(issues)

    for label, issues in (("narrative", narrative_tests()), ("table", table_tests())):
        status = "OK" if not issues else f"{len(issues)} issue(s)"
        print(f"[{status:>12}] {label}")
        for issue in issues:
            print(f"               - {issue}")
        all_issues.extend(issues)

    print(f"\nOutput written to {OUT}")
    print("TOTAL ISSUES:", len(all_issues))
    return 1 if all_issues else 0


if __name__ == "__main__":
    raise SystemExit(main())
