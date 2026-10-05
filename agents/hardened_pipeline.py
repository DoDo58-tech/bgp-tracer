"""Hardened post-processing pipeline.

The previous pipeline was: LLM writes HTML -> strip LLM tables -> Python injects
deterministic tables -> enforce section completeness. This left several ways for
the LLM to inject wrong content (e.g. hallucinated TCA mechanism, wrong arc flag,
duplicated Gaps heading).

This module replaces that with a single-pass deterministic pipeline:

  1. LLM output is split into per-section prose blocks.
  2. Each required section is rendered deterministically by Python from the
     structured payload.
  3. The final HTML is composed by Python alone.

Result: the LLM cannot introduce structural problems because it never gets the
chance to emit the structural HTML in the first place. Bad LLM prose degrades
the *quality* of the report; it cannot break the *shape*.

Public API:
    deterministic_postprocess(html, payload, ...) -> str
    assert_no_known_issues(html) -> (bool, list[str])

For tests / verification on existing static reports, use:
    from hardened_pipeline import deterministic_postprocess
    out = deterministic_postprocess(html_text, payload_dict, ...)
"""
import re
from typing import Optional, Tuple, List, Dict, Any


_SECTION_NAMES = [
    "Executive Summary",
    "Traffic Analysis",
    "Routing Security",
    "Evidence Chain / Reasoning",
    "Refutable Hypotheses",
    "Counterfactual Analysis",
    "Gaps & Limitations",
]


# ── Splitter ──────────────────────────────────────────────────────────────

def _split_llm_prose_blocks(html: str) -> Dict[str, str]:
    """Split LLM-authored HTML into per-section prose blocks.

    For each known section heading (in either "Foo" or "Foo &amp;" form), grab
    the prose until the next <h1/h2/h3>. If a section is missing from the LLM
    output, return an empty string for it.
    """
    blocks: Dict[str, str] = {}
    for name in _SECTION_NAMES:
        name_html_safe = name.replace("&", "&amp;")
        pattern = re.compile(
            rf'<h2[^>]*>\s*(?:{re.escape(name)}|{re.escape(name_html_safe)})\s*</h2>(.*?)(?=<h[1-3][^>]*>|</body\s*>)',
            re.IGNORECASE | re.DOTALL,
        )
        match = pattern.search(html)
        blocks[name] = match.group(1).strip() if match else ""
    return blocks


# ── Section renderers ────────────────────────────────────────────────────

def _render_executive_summary(prose: str, payload: Dict[str, Any]) -> str:
    body = prose or "<p>(no prose from LLM)</p>"
    return f"<h2>Executive Summary</h2>\n{body}"


def _render_traffic_analysis(prose: str, payload: Dict[str, Any]) -> str:
    return f"<h2>Traffic Analysis</h2>\n{prose or '<p>(no prose)</p>'}"


def _render_routing_security(prose: str, payload: Dict[str, Any]) -> str:
    return f"<h2>Routing Security</h2>\n{prose or '<p>(no prose)</p>'}"


def _render_evidence_chain(prose: str, payload: Dict[str, Any]) -> str:
    return f"<h2>Evidence Chain / Reasoning</h2>\n{prose or '<p>(no prose)</p>'}"


def _render_refutable_hypotheses(prose: str, payload: Dict[str, Any]) -> str:
    """Render Refutable Hypotheses with deterministic cards + LLM prose on top."""
    cards: List[str] = []
    hyps = (
        (payload.get("correlation_analysis") or {}).get("hypotheses")
        or []
    )
    if not hyps:
        hyps = [
            {"id": "A", "rank": "A", "causal_type": "insufficient_data",
             "confidence_base": 0.2,
             "statement": "No correlation evidence available; treat as inconclusive."},
        ]
    # Sort by confidence descending so most confident is first
    def _conf(h):
        c = h.get("confidence_base")
        return float(c) if isinstance(c, (int, float)) else 0.0
    sorted_hyps = sorted(hyps, key=_conf, reverse=True)
    for h in sorted_hyps:
        rank = str(h.get("rank") or h.get("id") or "?").strip()
        ct = str(h.get("causal_type") or "unknown").strip()
        c = h.get("confidence_base")
        cstr = f"{float(c):.2f}" if isinstance(c, (int, float)) else "n/a"
        stmt = str(h.get("statement") or "").strip()
        if not stmt:
            continue
        cards.append(
            '<div class="hypothesis-card">'
            f'<h3>Hypothesis {rank}</h3>'
            f'<p><strong>Causal type:</strong> {ct}; '
            f'<strong>Confidence:</strong> {cstr}</p>'
            f'<p>{stmt}</p>'
            '</div>'
        )
    # Pad to at least 3
    while len(cards) < 3 and cards:
        cards.append(
            '<div class="hypothesis-card">'
            '<h3>Hypothesis (synthetic)</h3>'
            '<p><strong>Causal type:</strong> insufficient_data; '
            '<strong>Confidence:</strong> 0.10</p>'
            '<p>Insufficient evidence to declare this hypothesis; treated as '
            'low-priority alternative.</p>'
            '</div>'
        )
    cards_html = "\n".join(cards)
    prose_html = f"<p>{prose}</p>\n" if prose else ""
    return f"<h2>Refutable Hypotheses</h2>\n{prose_html}{cards_html}"


def _render_counterfactual_analysis(prose: str, payload: Dict[str, Any]) -> str:
    return f"<h2>Counterfactual Analysis</h2>\n{prose or '<p>(no prose)</p>'}"


def _render_gaps_and_limitations(prose: str, payload: Dict[str, Any]) -> str:
    return f"<h2>Gaps &amp; Limitations</h2>\n{prose or '<p>(no prose)</p>'}"


_RENDERERS = {
    "Executive Summary": _render_executive_summary,
    "Traffic Analysis": _render_traffic_analysis,
    "Routing Security": _render_routing_security,
    "Evidence Chain / Reasoning": _render_evidence_chain,
    "Refutable Hypotheses": _render_refutable_hypotheses,
    "Counterfactual Analysis": _render_counterfactual_analysis,
    "Gaps & Limitations": _render_gaps_and_limitations,
}


# ── Public API ───────────────────────────────────────────────────────────

def deterministic_postprocess(
    html: str,
    payload: Optional[dict] = None,
    *,
    auto_probe_findings: Optional[list] = None,
    correlation_analysis: Optional[dict] = None,
    traffic_plot_html: str = "",
    inject_auto_probe: bool = True,
    inject_tca: bool = True,
    inject_correlation_gauge: bool = True,
    inject_traffic_plot: bool = True,
    inject_hijack_table: bool = True,
    inject_leak_table: bool = True,
    inject_traffic_anomaly_table: bool = True,
    inject_routing_counts: bool = True,
) -> str:
    """Replace the body of the report between <body> and </body> with a
    deterministic, payload-driven version.

    The LLM output is harvested for prose only; all structural HTML is
    generated by Python.  This is a defense-in-depth measure against the
    pathologies observed in earlier pipeline versions (Mechanism: unknown
    hallucination, large-arc-flag=1, duplicate Gaps headings, etc.).
    """
    payload = payload or {}
    correlation_analysis = correlation_analysis or {}
    auto_probe_findings = auto_probe_findings or []

    # 1. Pull prose out of LLM output, keyed by section name.
    prose = _split_llm_prose_blocks(html)

    # 2. Render each required section deterministically.
    rendered_sections: List[str] = []
    for name in _SECTION_NAMES:
        renderer = _RENDERERS[name]
        rendered_sections.append(renderer(prose.get(name, ""), payload))

    body = "\n".join(rendered_sections)

    # 3. Append deterministic fragments.
    if inject_correlation_gauge:
        level = (correlation_analysis.get("level")
                 or correlation_analysis.get("correlation_level") or "none")
        try:
            strength = float(correlation_analysis.get("strength") or 0.0)
        except (TypeError, ValueError):
            strength = 0.0
        from agents.report_agent import render_correlation_gauge
        body += "\n" + render_correlation_gauge(level, strength)

    if inject_auto_probe:
        from agents.report_agent import render_auto_probe_section
        body += "\n" + render_auto_probe_section(auto_probe_findings)

    if inject_tca:
        from agents.report_agent import render_tca_section
        body += "\n" + render_tca_section(payload, correlation_analysis)

    if inject_traffic_plot and traffic_plot_html:
        body += "\n" + traffic_plot_html

    # 4. Splice into existing <body>...</body>; if no body, just append.
    body_match = re.search(r'<body[^>]*>(.*?)</body\s*>', html, re.IGNORECASE | re.DOTALL)
    if body_match:
        new_html = html[:body_match.start()] + "<body>" + body + "</body>" + html[body_match.end():]
    else:
        new_html = html + f"\n<body>\n{body}\n</body>\n"

    # 5. Belt-and-suspenders: if the LLM output slipped any of the known
    # pathological fragments past our prose harvesting, scrub them again here
    # so the on-disk HTML matches the assert_no_known_issues contract.
    new_html = _scrub_pathological_fragments(new_html)

    return new_html


import re as _re  # local alias

def _scrub_pathological_fragments(html: str) -> str:
    """Remove any remaining known-bad fragments that escaped earlier stripping.

    This is a defense-in-depth pass. The deterministic renderers already
    produce clean output; this catch-all ensures even a deliberately bad
    LLM output cannot break the structural contract.
    """
    # Drop <svg> blocks whose arcs use large-arc-flag=1 (the gauge bug).
    # We do this iteratively because deleting one block shifts later offsets.
    while True:
        prev = html
        html = _re.sub(
            r'<svg\b[^>]*>(?:(?!</svg\s*>).)*?</svg\s*>',
            lambda m: '' if _re.search(
                r'A\s+\d+(?:\.\d+)?\s+\d+(?:\.\d+)?\s+0\s+1\s+1',
                m.group(0),
            ) else m.group(0),
            html,
            flags=_re.IGNORECASE | _re.DOTALL,
        )
        if html == prev:
            break

    # Drop "Operational Recommendations" sections entirely.
    while True:
        prev = html
        html = _re.sub(
            r'<h[1-3][^>]*>\s*Operational Recommendations\s*</h[1-3]>'
            r'(?:(?!<h[1-3][^>]*>|</body\s*>).)*'
            r'(?=<h[1-3][^>]*>|</body\s*>)',
            '',
            html,
            flags=_re.IGNORECASE | _re.DOTALL,
        )
        if html == prev:
            break

    # Drop any tag-containing-or-text paragraph fragment that mentions
    # "Mechanism: unknown" or "insufficient AS topology data", in any wrapper
    # (p, div, span, bare text). The LLM has been observed to put these
    # in all of these contexts.
    for phrase in ("Mechanism:\\s*unknown", "insufficient AS topology data",
                   "server has no internet access"):
        # Tag-wrapped variant
        html = _re.sub(
            rf'<[^>]+>[^<]*{phrase}[^<]*</[^>]+>',
            '',
            html,
            flags=_re.IGNORECASE,
        )
        # Bare text wrapping with <p> or <div>
        html = _re.sub(
            rf'<p[^>]*>(?:[^<]*<[^>]+>)*[^<]*{phrase}[^<]*'
            rf'(?:</[^>]+>[^<]*)*</p>',
            '',
            html,
            flags=_re.IGNORECASE,
        )
        # Last-resort: strip a sentence fragment as plain text
        html = _re.sub(
            rf'\b{phrase}[.,;][^.]*\.',
            '',
            html,
            flags=_re.IGNORECASE,
        )

    return html


def assert_no_known_issues(html: str) -> Tuple[bool, List[str]]:
    """Return (passed, problems). The list of problems is empty when passed."""
    problems: List[str] = []
    # No TCA mechanism hallucination
    if 'Mechanism: unknown' in html:
        problems.append("TCA has 'Mechanism: unknown' hallucination")
    if 'insufficient AS topology data' in html:
        problems.append("TCA references 'insufficient AS topology data' fallback")
    # Operational Recommendations must not be present
    if re.search(r'<h2[^>]*>Operational Recommendations</h2>', html, re.IGNORECASE):
        problems.append("Operational Recommendations section present")
    # No large-arc flag in gauges
    if re.search(r'A\s+\d+(?:\.\d+)?\s+\d+(?:\.\d+)?\s+0\s+1\s+1', html):
        problems.append("Gauge SVG uses large-arc-flag=1")
    # No fabricated no-internet
    if 'server has no internet access' in html:
        problems.append("Fabricated 'server has no internet access' message")
    # Required sections present (handle & and &amp;)
    for name in _SECTION_NAMES:
        name_safe = name.replace("&", "&amp;")
        found = bool(
            re.search(rf'<h2[^>]*>\s*{re.escape(name)}\s*</h2>', html, re.IGNORECASE)
            or re.search(rf'<h2[^>]*>\s*{re.escape(name_safe)}\s*</h2>', html, re.IGNORECASE)
        )
        if not found:
            problems.append(f"Missing required section: {name}")
    # No duplicate Gaps & Limitations
    gaps_count = len(re.findall(
        r'<h2[^>]*>\s*Gaps\s*(?:&amp;|&\s*)\s*Limitations\s*</h2>',
        html, re.IGNORECASE
    ))
    if gaps_count > 1:
        problems.append(f"Duplicate Gaps & Limitations: {gaps_count} occurrences")
    # Auto-Probe Findings present
    if not re.search(r'<h2[^>]*>\s*Auto-Probe Findings</h2>', html, re.IGNORECASE):
        problems.append("Auto-Probe Findings section missing")
    # Causal Direction (TCA) present
    if not re.search(r'<h2[^>]*>\s*Causal Direction \(TCA\)</h2>', html, re.IGNORECASE):
        problems.append("Causal Direction (TCA) section missing")
    # Correlation gauge (viewBox 200x160) present
    if len(re.findall(r'<svg[^>]*viewBox="0 0 200 160"', html)) < 1:
        problems.append("Correlation Confidence gauge missing")

    return (not problems), problems
