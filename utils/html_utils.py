import re
from typing import List

def html_escape(text: str) -> str:
    if text is None:
        return ""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _format_inline(md: str) -> str:
    """Apply minimal inline markdown formatting: code, bold, italic."""
    if not md:
        return ""
    # inline code
    md = re.sub(r"`([^`]+)`", lambda m: f"<code>{html_escape(m.group(1))}</code>", md)
    # bold **text** or __text__
    md = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", md)
    md = re.sub(r"__(.+?)__", r"<strong>\1</strong>", md)
    # italic *text* or _text_
    md = re.sub(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)", r"<em>\1</em>", md)
    md = re.sub(r"(?<!_)_(?!_)(.+?)(?<!_)_(?!_)", r"<em>\1</em>", md)
    return md


def _render_table(lines: List[str], start_idx: int) -> (str, int):
    """Render a simple GitHub-style table block starting at start_idx.
    Returns (html, next_index_after_block).
    """
    headers = [cell.strip() for cell in lines[start_idx].strip().strip('|').split('|')]
    sep_line = lines[start_idx + 1].strip()
    if not re.match(r"^\|?\s*(:?-+\s*\|)+\s*:?-+\s*\|?$", sep_line):
        return "", start_idx

    rows: List[List[str]] = []
    i = start_idx + 2
    while i < len(lines):
        line = lines[i]
        if '|' not in line:
            break
        row = [cell.strip() for cell in line.strip().strip('|').split('|')]
        rows.append(row)
        i += 1

    # build html
    thead = "<thead><tr>" + "".join([f"<th>{html_escape(h)}</th>" for h in headers]) + "</tr></thead>"
    tbody_parts: List[str] = []
    for r in rows:
        tds = "".join([f"<td>{_format_inline(html_escape(c))}</td>" for c in r])
        tbody_parts.append(f"<tr>{tds}</tr>")
    tbody = "<tbody>" + "".join(tbody_parts) + "</tbody>"
    return f"<table>{thead}{tbody}</table>", i


def render_markdown_to_html(md_text: str) -> str:
    """Render a small subset of Markdown to HTML with sane spacing.
    Supports: #/##/###/#### headings, lists (-/*), hr (---), inline bold/italic/code, tables.
    """
    if not md_text:
        return "<em>No expert analysis available.</em>"

    lines = md_text.splitlines()
    html_parts: List[str] = []
    in_ul = False
    i = 0
    while i < len(lines):
        raw = lines[i]
        line = raw.rstrip()
        stripped = line.strip()

        # end list on blank/table/heading
        def end_ul():
            nonlocal in_ul
            if in_ul:
                html_parts.append("</ul>")
                in_ul = False

        # horizontal rule
        if stripped == '---':
            end_ul()
            html_parts.append("<hr/>")
            i += 1
            continue

        # tables
        if '|' in stripped and i + 1 < len(lines):
            maybe_table_html, next_i = _render_table(lines, i)
            if next_i != i:
                end_ul()
                html_parts.append(maybe_table_html)
                i = next_i
                continue

        # headings
        for level, prefix in ((4, '#### '), (3, '### '), (2, '## '), (1, '# ')):
            if stripped.startswith(prefix):
                end_ul()
                content = stripped[len(prefix):].strip()
                # strip surrounding **...** in heading content if present
                m_bold = re.match(r"^\*\*(.+)\*\*$", content)
                if m_bold:
                    content = m_bold.group(1).strip()
                html_parts.append(f"<h{level}>{html_escape(content)}</h{level}>")
                break
        else:
            # full-line bold treated as heading (common LLM style: **Title**)
            if re.match(r"^\*\*.+\*\*$", stripped):
                end_ul()
                content = stripped[2:-2].strip()
                html_parts.append(f"<h3>{html_escape(content)}</h3>")
            # lists
            if stripped.startswith('- ') or stripped.startswith('* '):
                if not in_ul:
                    html_parts.append("<ul>")
                    in_ul = True
                html_parts.append(f"<li>{_format_inline(html_escape(stripped[2:]))}</li>")
            elif stripped == "":
                end_ul()
                # collapse multiple blanks by doing nothing (CSS controls spacing)
            else:
                end_ul()
                html_parts.append(f"<p>{_format_inline(html_escape(stripped))}</p>")
        i += 1

    if in_ul:
        html_parts.append("</ul>")
    return "\n".join(html_parts)


def style_css() -> str:
    return (
        "body { font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 24px; line-height: 1.5; font-size: 16px; }"
        "h2 { margin: 0.2em 0 0.4em 0; font-size: 24px; }"
        "h3 { margin: 0.8em 0 0.4em 0; font-size: 20px; }"
        "h4 { margin: 0.6em 0 0.3em 0; font-size: 18px; }"
        "p { margin: 0.4em 0; }"
        "ul { margin: 0.4em 0 0.4em 1.2em; }"
        "table { border-collapse: collapse; width: 100%; margin: 0.6em 0; }"
        "th, td { border: 1px solid #ddd; padding: 6px 8px; text-align: left; }"
        "th { background: #fafafa; }"
        "code { background: #f6f8fa; padding: 2px 4px; border-radius: 4px; font-size: 14px; }"
        "pre { background: #f6f8fa; padding: 12px; border-radius: 6px; overflow: auto; font-size: 13px; }"
    )


