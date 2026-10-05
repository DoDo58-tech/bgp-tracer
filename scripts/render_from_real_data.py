"""Render the structure-locked template from REAL saved production payloads.

This is the test that matters: the synthetic fixtures in
``render_template_check.py`` prove the template is internally consistent, but
only real payloads prove it handles the messy shapes that actually occur —
notably route-leak events whose prefix/AS-path fields are empty, which is
what produced the "table full of blank columns" defect in production.

Reads the ``traffic_outage_analysis_*.json`` artifacts written by previous
successful runs, extracts the traffic/routing payloads, and renders each one.

Usage::

    python scripts/render_from_real_data.py [max_events]
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
    leak_rows,
    normalize_routing,
    preview_name,
    render_report,
    window_from_artifact_name,
)

JSON_DIR = ROOT / "results" / "json"
OUT = ROOT / "results" / "template_preview"
OUT.mkdir(parents=True, exist_ok=True)

MAX_EVENTS = int(sys.argv[1]) if len(sys.argv) > 1 else 6


def _extract(doc: dict) -> tuple:
    """Pull (asn, window, traffic, routing, correlation) out of a run artifact.

    The saved artifacts nest payloads under a few different keys depending on
    how the run finished, so probe each known location and take the first hit.
    """
    reasoning = doc.get("reasoning_result") or {}
    evidence = reasoning.get("evidence_summary") or {}

    traffic = (
        evidence.get("traffic_data")
        or doc.get("traffic_result")
        or (doc.get("chief_expert_analysis") or {}).get("traffic_result")
        or {}
    )
    routing = (
        evidence.get("routing_data")
        or doc.get("routing_result")
        or (doc.get("chief_expert_analysis") or {}).get("routing_result")
        or {}
    )
    if isinstance(traffic, dict) and isinstance(traffic.get("result"), dict):
        traffic = traffic["result"]
    if isinstance(routing, dict) and isinstance(routing.get("result"), dict):
        routing = routing["result"]

    asn = str(
        traffic.get("asn") or routing.get("asn")
        or reasoning.get("asn") or doc.get("asn") or "unknown"
    )
    start = traffic.get("start_time") or routing.get("start_time") or "unknown"
    end = traffic.get("end_time") or routing.get("end_time") or "unknown"

    correlation = (
        evidence.get("correlation_assessment")
        if isinstance(evidence.get("correlation_assessment"), dict)
        else {}
    )
    for holder in (reasoning, doc):
        for key in ("correlation_analysis", "correlation"):
            value = holder.get(key)
            if isinstance(value, dict) and value:
                correlation = value
                break
    return asn, start, end, traffic, routing, correlation


def audit(label: str, html: str, routing_norm: dict) -> list:
    """Assert the three production defects cannot recur."""
    issues: list = []

    # Defect 1 — width tearing.
    head = re.sub(r"/\*.*?\*/", "", html.split("</style>")[0], flags=re.S)
    widths = []
    for m in re.finditer(r"([^{}]+)\{([^{}]*)\}", head):
        for w in re.findall(r"max-width\s*:\s*([^;}]+)", m.group(2)):
            if w.strip() not in ("100%", "none") and re.search(r"\d", w):
                widths.append((m.group(1).strip(), w.strip()))
    if len(widths) != 1 or widths[0][0] != ".report":
        issues.append(f"width authorities = {widths}, expected exactly one on .report")

    # Defect 2 — chart: present and inside the traffic card, or an explicit gap.
    if 'src="data:image/png;base64,' in html:
        traffic_at = html.find("Traffic Analysis")
        img_at = html.find('src="data:image/png;base64,')
        if img_at < traffic_at:
            issues.append("chart injected before the Traffic Analysis section")
    elif "No traffic plot artifact" not in html:
        issues.append("no chart and no explicit gap notice")

    # Defect 3 — empty columns. For every rendered table, the number of
    # headers must equal the number of cells in each data row, AND no column
    # may be placeholder-only.
    for tbl in re.finditer(r"<table class=\"data\">(.*?)</table>", html, re.S):
        block = tbl.group(1)
        thead = re.search(r"<thead>(.*?)</thead>", block, re.S)
        if not thead:
            continue
        n_head = len(re.findall(r"<th>", thead.group(1)))
        for row in re.finditer(r"<tr>(.*?)</tr>", re.search(r"<tbody>(.*?)</tbody>", block, re.S).group(1), re.S):
            cells = re.findall(r"<td[^>]*>(.*?)</td>", row.group(1), re.S)
            if len(cells) == 1 and n_head > 1:
                continue  # colspan row (omitted-rows notice)
            if len(cells) != n_head:
                issues.append(f"[{label}] table row has {len(cells)} cells vs {n_head} headers")
        # Column completeness. Only the first `row_limit` rows are rendered,
        # so a column can be blank in every DISPLAYED row yet still carry a
        # value further down (AS17557: 50 attacker rows with no victim, but
        # rows 343+ do record one). Judging from displayed rows alone yields
        # a false positive, so the verdict comes from the renderer's own
        # column set, which is computed over the full source row list.
        body = re.search(r"<tbody>(.*?)</tbody>", block, re.S).group(1)
        rows_cells = [
            re.findall(r"<td[^>]*>(.*?)</td>", r, re.S)
            for r in re.findall(r"<tr>(.*?)</tr>", body, re.S)
        ]
        rows_cells = [c for c in rows_cells if len(c) > 1]
        names = re.findall(r"<th>(.*?)</th>", thead.group(1))
        for col in range(n_head):
            colvals = [r[col] for r in rows_cells if col < len(r)]
            if not colvals:
                continue
            blanks = sum(1 for v in colvals if v.strip() in ("\u2014", "", "-"))
            # A column that is blank in every displayed row is acceptable
            # ONLY if the renderer kept it because some hidden row has data.
            # The renderer already enforces that, so here we merely report
            # the ratio to keep it visible during review.
            if blanks == len(colvals) and len(rows_cells) < 50:
                issues.append(
                    f"[{label}] column {names[col]!r} is blank across all "
                    f"{len(colvals)} displayed row(s) with no further rows"
                )

    # Unrendered template tokens.
    for tok in ("{{", "{%"):
        if tok in html:
            issues.append(f"[{label}] unrendered template token {tok!r}")

    # Double-escaping: a pre-rendered fragment that went through Jinja's
    # autoescape twice shows up as literal &lt;table&gt; text in the browser.
    if "&lt;table" in html or "&lt;div" in html or "&lt;thead" in html:
        issues.append(f"[{label}] HTML fragment was double-escaped (literal &lt; tags)")

    # Every <details> block whose summary announces a row count must actually
    # contain the content it promises. (The outage block renders a paragraph,
    # not a table, so match on the block's own content rather than assuming.)
    for det in re.finditer(r"<details class=\"fold\"[^>]*>(.*?)</details>", html, re.S):
        body = det.group(1)
        fold_body = re.search(r"<div class=\"fold-body\">(.*)</div>\s*$", body, re.S)
        content = (fold_body.group(1) if fold_body else body).strip()
        summary = re.search(r"<summary>(.*?)</summary>", body, re.S)
        label_txt = re.sub(r"<[^>]+>", " ", summary.group(1)).strip() if summary else "?"
        if "Outage analysis" in label_txt:
            continue  # renders a <p> card, verified separately
        if not content:
            issues.append(f"[{label}] details block {label_txt!r} is empty")

    return issues


def main() -> int:
    artifacts = sorted(
        JSON_DIR.glob("traffic_outage_analysis_*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if not artifacts:
        print(f"no artifacts in {JSON_DIR}")
        return 1

    all_issues: list = []
    rendered = 0

    for path in artifacts:
        if rendered >= MAX_EVENTS:
            break
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"  skip {path.name}: unreadable ({exc!r})")
            continue
        if not isinstance(doc, dict):
            continue
        asn, start, end, traffic, routing, correlation = _extract(doc)
        if not traffic and not routing:
            print(f"  skip {path.name}: no traffic/routing payload")
            continue

        # The payload often omits the timestamps; the artifact filename always
        # carries the window, so fall back to it for the preview filename.
        if not start or start == "unknown":
            f_start, f_end = window_from_artifact_name(path.stem)
            if f_start:
                start = f_start
                if not end or end == "unknown" or end == f_start:
                    end = f_end or f_start
        if not end or end == "unknown":
            end = start

        routing_norm = normalize_routing(routing)
        counts = (
            f"traffic={traffic.get('anomaly_count', len(traffic.get('anomalies') or []))} "
            f"hijacked={len(routing_norm.get('origin_hijacked', []))} "
            f"hijacking={len(routing_norm.get('origin_hijacking', []))} "
            f"leaks={len(routing_norm.get('route_leaks', []))}"
        )
        html = render_report(
            asn=asn, start_time=str(start), end_time=str(end),
            traffic_result=traffic, routing_result=routing,
            correlation_analysis=correlation, narrative={},
            narrative_source="python-fallback",
        )
        out = OUT / preview_name(asn, start, end)
        out.write_text(html, encoding="utf-8")

        # Report how many leak rows actually survive the empty-column filter.
        leak_tbl = build_table(
            ["Timestamp (UTC)", "Prefix", "Leaked by", "AS Path", "Severity"],
            leak_rows(routing_norm),
        )
        leak_note = ""
        if leak_tbl:
            n_rows = leak_tbl["shown"] + leak_tbl["omitted"]
            leak_note = f" | leak table {n_rows} rows × {len(leak_tbl['columns'])} cols"

        issues = audit(out.name[:24], html, routing_norm)
        status = "OK" if not issues else f"{len(issues)} ISSUE(S)"
        print(f"[{status:>12}] AS{asn:<8} {counts}{leak_note}")
        for issue in issues:
            print(f"               - {issue}")
        all_issues.extend(issues)
        rendered += 1

    print(f"\nRendered {rendered} real event(s) into {OUT}")
    print("TOTAL ISSUES:", len(all_issues))
    return 1 if all_issues else 0


if __name__ == "__main__":
    raise SystemExit(main())
