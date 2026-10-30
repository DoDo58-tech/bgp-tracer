"""JSON-key scrubber for the LLM-rendered HTML report."""
from __future__ import annotations

import re

from agents.report_postprocess import (
    _CJK_CHAR,
    _NO_DATA_PATTERNS,
    strip_table_nodata_rows,
)


_JSON_KEY_PLACEHOLDER_RE = re.compile(r"\[(?P<key>[^\[\]:\s]+)\]")


def scrub_json_key_placeholders(html: str, asn: str = "",
                                  start_time: str = "", end_time: str = "") -> str:
    """Substitute well-known JSON-key placeholders with their actual values."""
    if not html:
        return html

    def repl(m):
        key = m.group("key")
        if key in ("target_as", "target_asn", "asn"):
            return asn if asn else "(no data)"
        if key == "user_analysis_window":
            if not start_time or not end_time:
                return "(no data)"
            return f"{start_time} to {end_time}"
        if key == "start_time":
            return start_time or "(no data)"
        if key == "end_time":
            return end_time or "(no data)"
        return "(no data)"

    return _JSON_KEY_PLACEHOLDER_RE.sub(repl, html)


def strip_nodata_artifacts(html):
    """Best-effort cleanup so reports don't show "(no data)" rows / cells."""
    if not html:
        return html

    # 1. Strip empty table rows.
    def strip_table_block(m):
        block = m.group(0)
        tbody_m = re.search(r"<tbody\b[^>]*>(.*?)</tbody>", block, flags=re.DOTALL | re.IGNORECASE)
        if not tbody_m:
            return block
        tbody_before = block[:tbody_m.start()]
        stripped = strip_table_nodata_rows(tbody_m.group(1))
        return tbody_before + "<tbody>" + stripped + "</tbody>" + block[tbody_m.end():]

    html = re.sub(r"<table\b[^>]*>.*?</table>", strip_table_block, html,
                   flags=re.DOTALL | re.IGNORECASE)

    # 2. Replace no-data tokens inside cells with em-dash.
    for pat in _NO_DATA_PATTERNS:
        html = pat.sub("—", html)

    # 3. Drop Three-Card tier if all three cards are UNAVAILABLE.
    def drop_unavailable_tier(m):
        return "" if m.group(0).count("UNAVAILABLE") >= 3 else m.group(0)

    html = re.sub(
        r"<div\s+class=\"three-card-tier\"[^>]*>.*?</div>\s*(?=</div>|$)",
        drop_unavailable_tier,
        html,
        flags=re.DOTALL | re.IGNORECASE,
    )

    # 4. Strip CJK characters.
    html = _CJK_CHAR.sub("", html)

    # 5. Collapse sequences of em-dashes.
    html = re.sub(r"—\s*—\s*—", "—", html)

    # 6. Remove empty paragraphs / spans.
    html = re.sub(r"<p[^>]*>\s*</p>", "", html, flags=re.IGNORECASE)
    html = re.sub(r"<span[^>]*>\s*</span>", "", html, flags=re.IGNORECASE)

    # 7. Fix broken HTML the LLM sometimes emits.
    html = re.sub(r"<table\b(?![^>]*>)", "<table>", html, flags=re.IGNORECASE)
    html = re.sub(r"<tr\b(?![^>]*>)", "<tr>", html, flags=re.IGNORECASE)
    html = re.sub(r"<td\b(?![^>]*>)", "<td>", html, flags=re.IGNORECASE)
    html = re.sub(r"<th\b(?![^>]*>)", "<th>", html, flags=re.IGNORECASE)

    # 8. Fix <tr>X</tr> where X doesn't start with <td> or <th>.
    html = re.sub(
        r"<tr>(?!<t[dh])((?:(?!</tr>).)*?)</tr>",
        r"<tr><td>\1</td></tr>",
        html,
        flags=re.IGNORECASE | re.DOTALL,
    )

    # 9. Split single-cell rows that contain multiple space-separated tokens.
    def split_single_td(m, html=html):
        cell_text = m.group(1).strip()
        if cell_text.count(" ") < 2:
            return m.group(0)
        thead_m = re.search(
            r"<thead\b[^>]*>(.*?)</thead>",
            html[:m.start()],
            flags=re.DOTALL | re.IGNORECASE,
        )
        header_cells = []
        if thead_m:
            header_cells = re.findall(
                r"<th\b[^>]*>(.*?)</th>",
                thead_m.group(1),
                flags=re.DOTALL | re.IGNORECASE,
            )
        n_cols = max(1, len(header_cells))
        tokens = cell_text.split()
        if len(tokens) <= n_cols:
            return m.group(0)
        chunks = [" ".join(tokens[i:i + 1]) for i in range(n_cols - 1)]
        chunks.append(" ".join(tokens[n_cols - 1:]))
        new_tds = "".join(f"<td>{c}</td>" for c in chunks)
        return m.group(0).replace(f"<td>{cell_text}</td>", new_tds, 1)

    html = re.sub(
        r"<tr>\s*<td>((?:(?!</td>).)*?)</td>\s*</tr>",
        split_single_td,
        html,
        flags=re.DOTALL,
    )
    return html