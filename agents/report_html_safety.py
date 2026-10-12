"""HTML safety net for the LLM-rendered HTML report.

Extracted from agents/report_agent.py.  Three concerns:

  1. ``_repair_missing_lt`` restores the leading ``<`` of known HTML
     tags that the LLM dropped (a known Qwen / GLM bug).
  2. ``validate_html_balance`` returns ``(ok, problems)`` for a
     candidate HTML body — used to decide whether to apply the
     deterministic-fallback path.
  3. ``_auto_close_unbalanced_html`` appends ``</tag>`` for unclosed
     elements at document end, without modifying existing content.
"""
from __future__ import annotations

import re


_HTML_TAGS_ALLOWED_TO_REPAIR = (
    "html", "head", "body", "div", "p", "span", "strong", "em",
    "h1", "h2", "h3", "h4", "h5", "h6", "ul", "ol", "li",
    "table", "thead", "tbody", "tr", "td", "th",
    "section", "article", "header", "footer", "main",
    "blockquote", "pre", "code",
)
_REPAIR_OPEN_TAG = re.compile(
    r"(?<!<)(?<!/)(\b(?:" + "|".join(_HTML_TAGS_ALLOWED_TO_REPAIR) +
    r")\b(?:[ \t][^<>]{0,200}?)?)(?=\s*>|$)"
)
_REPAIR_CLOSE_TAG = re.compile(
    r"(?<!<)/(?:(?:" + "|".join(_HTML_TAGS_ALLOWED_TO_REPAIR) + r"))\s*>"
)
_DOCTYPE_RE = re.compile(r"<!DOCTYPE\b[^>]*>", re.IGNORECASE)
_REPAIR_COMMENT_OPEN = re.compile(r"(?<!<)(!--(?:[^-]|-(?!-))*?-->)")
_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)


def _repair_missing_lt(html: str) -> str:
    """Restore ``<`` characters the LLM dropped before known HTML tags.

    Also restores ``<!-- ... -->`` HTML comment markers whose leading
    ``<`` was dropped (Qwen/GLM bug observed in production).
    """
    if not html:
        return html

    doctype_match = _DOCTYPE_RE.search(html)
    doctype_masked = html
    if doctype_match:
        token = "\x00DOCTYPE\x00"
        doctype_masked = html[:doctype_match.start()] + token + html[doctype_match.end():]

    comment_matches = list(_COMMENT_RE.finditer(doctype_masked))
    comment_map = []
    comment_masked = doctype_masked
    for idx, m in enumerate(comment_matches):
        placeholder = f"\x00COMM{idx}\x00"
        comment_map.append((placeholder, m.group(0)))
        comment_masked = comment_masked.replace(m.group(0), placeholder, 1)

    def _open_sub(match: re.Match) -> str:
        start = match.start()
        if start > 0 and comment_masked[start - 1].isalnum():
            return match.group(0)
        return "<" + match.group(1)

    repaired = _REPAIR_OPEN_TAG.sub(_open_sub, comment_masked)
    repaired = _REPAIR_CLOSE_TAG.sub(
        lambda m: "</" + m.group(0).lstrip("/"),
        repaired,
    )
    repaired = _REPAIR_COMMENT_OPEN.sub(lambda m: "<" + m.group(1), repaired)
    if doctype_match:
        repaired = repaired.replace("\x00DOCTYPE\x00", doctype_match.group(0))
    for placeholder, original in comment_map:
        repaired = repaired.replace(placeholder, original, 1)
    return repaired


def validate_html_balance(html: str) -> "tuple[bool, list[str]]":
    """Return ``(ok, problems)`` for a candidate HTML body.

    ``ok`` is True when the document has no unclosed tags and no
    mismatched closing tags.  ``problems`` is a human-readable list of
    issues for the log.  We use a hand-written scanner rather than
    :class:`html.parser.HTMLParser` because the stdlib parser silently
    auto-closes unclosed ancestors on ``</body>``, which hides the very
    class of bug we want to detect.
    """
    if not html:
        return False, ["empty html"]
    problems = []
    stack = []
    _STRUCTURAL = {"html", "body", "head"}
    void_tags = {
        "area", "base", "br", "col", "embed", "hr", "img", "input",
        "link", "meta", "param", "source", "track", "wbr",
    }
    _HTML5_OPTIONAL_END = {
        "p", "li", "tr", "td", "th", "dt", "dd",
        "rb", "rp", "rt", "rtc", "option", "thead", "tbody", "tfoot",
        "caption", "colgroup",
        "ul", "ol", "dl",
        "h1", "h2", "h3", "h4", "h5", "h6",
        "section", "div", "article", "aside", "header", "footer",
        "nav", "main", "figure", "figcaption", "details", "summary",
    }
    tag_re = re.compile(
        r"<!--.*?-->|<!DOCTYPE[^>]*>|"
        r"<\s*(?P<close>/)?\s*(?P<tag>[a-zA-Z][a-zA-Z0-9:-]*)(?:\s[^<>]*?)?\s*(?P<self>/)?\s*>",
        re.DOTALL,
    )
    _STRIP_BASE64_RE = re.compile(
        r'<img\b[^>]*?src="data:image/[^"]*;base64,[^"]*"\s*/?>', re.DOTALL,
    )
    _STRIP_RAW_TEXT_RE = re.compile(
        r"<(style|script)\b[^>]*>.*?</\1\s*>", re.DOTALL | re.IGNORECASE,
    )
    _STRIP_TITLE_RE = re.compile(
        r"<title\b[^>]*>.*?</title\s*>", re.DOTALL | re.IGNORECASE,
    )
    _STRIP_SVG_RE = re.compile(
        r"<svg\b[^>]*>.*?</svg\s*>", re.DOTALL | re.IGNORECASE,
    )
    _STRIP_PRE_RE = re.compile(
        r"<pre\b[^>]*>.*?</pre\s*>", re.DOTALL | re.IGNORECASE,
    )
    _STRIP_CODE_RE = re.compile(
        r"<code\b[^>]*>.*?</code\s*>", re.DOTALL | re.IGNORECASE,
    )
    html_for_scan = _STRIP_BASE64_RE.sub("[traffic chart placeholder]", html)
    html_for_scan = _STRIP_RAW_TEXT_RE.sub("[raw-text-block]", html_for_scan)
    html_for_scan = _STRIP_TITLE_RE.sub("<title></title>", html_for_scan)
    html_for_scan = _STRIP_SVG_RE.sub("[svg-block]", html_for_scan)
    html_for_scan = _STRIP_PRE_RE.sub("[pre-block]", html_for_scan)
    html_for_scan = _STRIP_CODE_RE.sub("[code-block]", html_for_scan)

    for match in tag_re.finditer(html_for_scan):
        if match.group(0).startswith("<!"):
            continue
        is_close = match.group("close") == "/"
        is_self_close = match.group("self") == "/"
        tag = match.group("tag").lower()
        if tag in void_tags or tag in _STRUCTURAL:
            continue
        if is_close:
            if stack and stack[-1][0] == tag:
                stack.pop()
                continue
            for i in range(len(stack) - 1, -1, -1):
                if stack[i][0] == tag:
                    dropped = stack[i + 1:]
                    stack = stack[:i]
                    for d_tag, d_off in dropped:
                        if d_tag not in _HTML5_OPTIONAL_END:
                            problems.append(
                                f"unclosed <{d_tag}> (auto-closed to match </{tag}> "
                                f"at offset {match.start()})"
                            )
                    break
            else:
                if tag in _HTML5_OPTIONAL_END:
                    continue
                if tag in {"div", "section", "article", "aside", "header",
                           "footer", "nav", "main", "figure", "details",
                           "summary"}:
                    continue
                problems.append(f"mismatched </{tag}> at offset {match.start()}")
        elif not is_self_close:
            stack.append((tag, match.start()))
    for tag, offset in stack:
        if tag in _HTML5_OPTIONAL_END:
            continue
        problems.append(f"unclosed <{tag}> at offset {offset}")
    return (len(problems) == 0), problems


def _auto_close_unbalanced_html(html: str) -> str:
    """Insert closing tags for any unclosed elements at document end.

    The LLM often leaves ``<li>`` / ``<ul>`` / ``<ol>`` / headings open
    when it runs out of tokens.  Browsers tolerate this (the next
    block-level element implicitly closes them) but the balance
    validator sees it as unbalanced and used to trigger the
    deterministic-fallback path.
    """
    if not html:
        return html
    void_tags = {
        "area", "base", "br", "col", "embed", "hr", "img", "input",
        "link", "meta", "param", "source", "track", "wbr",
    }
    optional_end = {
        "p", "li", "tr", "td", "th", "dt", "dd",
        "rb", "rp", "rt", "rtc", "option", "thead", "tbody", "tfoot",
        "caption", "colgroup",
        "ul", "ol", "dl",
        "h1", "h2", "h3", "h4", "h5", "h6",
    }
    _SKIP_AUTO_CLOSE = optional_end | {"li"}
    tag_re = re.compile(
        r"<!--.*?-->|<!DOCTYPE[^>]*>|"
        r"<\s*(?P<close>/)?\s*(?P<tag>[a-zA-Z][a-zA-Z0-9:-]*)(?:\s[^<>]*?)?\s*(?P<self>/)?\s*>",
        re.DOTALL,
    )
    _STRIP_RAW_TEXT_RE = re.compile(
        r"<(style|script|title)\b[^>]*>.*?</\1\s*>", re.DOTALL | re.IGNORECASE,
    )
    _STRIP_SVG_RE = re.compile(
        r"<svg\b[^>]*>.*?</svg\s*>", re.DOTALL | re.IGNORECASE,
    )
    _STRIP_PRE_RE = re.compile(
        r"<pre\b[^>]*>.*?</pre\s*>", re.DOTALL | re.IGNORECASE,
    )
    _STRIP_CODE_RE = re.compile(
        r"<code\b[^>]*>.*?</code\s*>", re.DOTALL | re.IGNORECASE,
    )
    html_for_scan = _STRIP_RAW_TEXT_RE.sub("[raw-text-block]", html)
    html_for_scan = _STRIP_SVG_RE.sub("[svg-block]", html_for_scan)
    html_for_scan = _STRIP_PRE_RE.sub("[pre-block]", html_for_scan)
    html_for_scan = _STRIP_CODE_RE.sub("[code-block]", html_for_scan)
    stack: list = []
    for m in tag_re.finditer(html_for_scan):
        if m.group(0).startswith("<!"):
            continue
        is_close = m.group("close") == "/"
        is_self_close = m.group("self") == "/"
        tag = m.group("tag").lower()
        if tag in void_tags:
            continue
        if is_close:
            for i in range(len(stack) - 1, -1, -1):
                if stack[i][0] == tag:
                    stack = stack[:i]
                    break
        elif not is_self_close:
            stack.append((tag, m.start()))
    closers = []
    for tag, _off in stack:
        if tag in _SKIP_AUTO_CLOSE or tag in {"html", "body", "head"}:
            continue
        closers.append(tag)
    if not closers:
        return html
    closer_html = "".join(f"</{t}>" for t in reversed(closers))
    body_close_re = re.compile(r"</body\s*>", re.IGNORECASE)
    m = body_close_re.search(html)
    if m:
        return html[:m.start()] + closer_html + html[m.start():]
    html_close_re = re.compile(r"</html\s*>", re.IGNORECASE)
    m = html_close_re.search(html)
    if m:
        return html[:m.start()] + closer_html + html[m.start():]
    return html + closer_html
