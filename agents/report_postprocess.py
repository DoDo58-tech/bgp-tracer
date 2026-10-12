"""Post-processing helpers for the LLM-rendered HTML report.

Extracted from agents/report_agent.py to keep that module under the
few-thousand-lines mark.  Functions here handle three concerns that
all happen AFTER the LLM returns its raw HTML:

  1. Strip ``(no data)`` placeholder rows and cells.
  2. Substitute ``[field.path]`` citation markers with the resolved
     value from the structured payload.
  3. Format scalar values for display.
"""
from __future__ import annotations

import re
from typing import Any, Optional


_NO_DATA_PATTERNS = [
    re.compile(r"\(no data\)", re.IGNORECASE),
    re.compile(r"\(N/?A\)", re.IGNORECASE),
    re.compile(r"\(unresolved\)", re.IGNORECASE),
    re.compile(r"\(unavailable\)", re.IGNORECASE),
    re.compile(r"\(insufficient baseline\)", re.IGNORECASE),
    re.compile(r"\(no traffic anomaly window detected\)", re.IGNORECASE),
    # Standalone em-dash / en-dash markers — the prompt tells the LLM to render
    re.compile(r"^\s*[—–\-]\s*$"),
]
_CJK_CHAR = re.compile(r"[\u4e00-\u9fff]")
_EMPTY_TD = re.compile(r"<td[^>]*>\s*(?:&nbsp;|\s)*\s*</td>", re.IGNORECASE)


def _cell_has_nodata(cell: str) -> bool:
    """True if every visible token in the cell is one of the (no data) variants."""
    text = re.sub(r"<[^>]+>", "", cell).strip()
    if not text:
        return True
    for pat in _NO_DATA_PATTERNS:
        text = pat.sub("", text).strip()
    return not text


def _strip_table_nodata_rows(table: str) -> str:
    """Drop <tr> rows where every cell is a (no data)/(N/A) placeholder,
    AND drop rows whose *first data* cell (typically Value column) is a
    no-data placeholder even if other columns have real values.

    `table` is the *inner* HTML between <table ...> and </table>.
    """
    out_chunks = []
    pos = 0
    for tr_match in re.finditer(r"<tr\b[^>]*>(.*?)</tr>", table, flags=re.DOTALL | re.IGNORECASE):
        out_chunks.append(table[pos:tr_match.start()])
        pos = tr_match.end()
        tr_inner = tr_match.group(1)
        if re.search(r"<th\b", tr_inner, flags=re.IGNORECASE):
            out_chunks.append(tr_match.group(0))
            continue
        cells = re.findall(r"<td\b[^>]*>(.*?)</td>", tr_inner, flags=re.DOTALL | re.IGNORECASE)
        if not cells:
            out_chunks.append(tr_match.group(0))
            continue
        if all(_cell_has_nodata(f"<td>{c}</td>") for c in cells):
            continue
        if len(cells) >= 2 and _cell_has_nodata(f"<td>{cells[1]}</td>"):
            continue
        cell_idx = 0

        def _sub_one(m, cells=cells):
            nonlocal cell_idx
            if cell_idx >= len(cells):
                return m.group(0)
            cleaned = cells[cell_idx]
            for pat in _NO_DATA_PATTERNS:
                cleaned = pat.sub("—", cleaned)
            cell_idx += 1
            return f"<td{m.group(1)}>{cleaned}</td>"

        new_tr = re.sub(r"<td\b([^>]*)>(.*?)</td>", _sub_one, tr_match.group(0), flags=re.DOTALL | re.IGNORECASE)
        out_chunks.append(new_tr)
    out_chunks.append(table[pos:])
    return "".join(out_chunks)


def _substitute_field_references(
    html: str,
    traffic: dict,
    routing: dict,
    reasoning: dict,
    traffic_anomaly_window: Optional[dict] = None,
    extra: Optional[dict] = None,
) -> str:
    """Substitute literal [field.path] citation markers in LLM HTML output."""
    if not html:
        return html

    traffic_section = traffic if isinstance(traffic, dict) else {}
    routing_section = routing if isinstance(routing, dict) else {}
    reasoning_section = reasoning if isinstance(reasoning, dict) else {}
    taw_section = traffic_anomaly_window if isinstance(traffic_anomaly_window, dict) else {}
    if not taw_section and isinstance(traffic, dict):
        taw_section = traffic.get("traffic_anomaly_window") if isinstance(traffic.get("traffic_anomaly_window"), dict) else {}

    payload_root: dict = {
        "traffic": traffic_section,
        "routing": routing_section,
        "reasoning": reasoning_section,
        "traffic_anomaly_window": taw_section,
    }
    if isinstance(extra, dict):
        for ek, ev in extra.items():
            if ek not in payload_root and ev is not None:
                payload_root[ek] = ev

    def _tokenise(filepath: str):
        tokens: list = []
        buf = ""
        i = 0
        while i < len(filepath):
            ch = filepath[i]
            if ch == ".":
                if buf:
                    tokens.append(buf); buf = ""
            elif ch == "[":
                if buf:
                    tokens.append(buf); buf = ""
                j = filepath.find("]", i)
                if j < 0:
                    return None
                idx_str = filepath[i + 1:j].strip()
                if not idx_str.isdigit():
                    return None
                tokens.append(int(idx_str))
                i = j
            else:
                buf += ch
            i += 1
        if buf:
            tokens.append(buf)
        return tokens

    def _walk(cur, tokens):
        for tok in tokens:
            if isinstance(cur, dict):
                if tok not in cur:
                    return None
                cur = cur[tok]
            elif isinstance(cur, list):
                if not isinstance(tok, int) or tok < 0 or tok >= len(cur):
                    return None
                cur = cur[tok]
            else:
                return None
        return cur

    def _summarise_collection(value, max_items: int = 3, max_len: int = 60) -> str:
        if isinstance(value, list):
            n = len(value)
            if n == 0:
                return "0 items"
            scalars = [str(x) for x in value[:max_items] if not isinstance(x, (dict, list))]
            if scalars:
                preview = ", ".join(scalars[:max_items])
                if n > max_items:
                    return f"{preview}, … ({n} total)"
                if len(preview) > max_len:
                    return f"{n} item{'s' if n != 1 else ''}"
                return f"{preview} ({n} total)" if n > max_items else preview
            return f"{n} item{'s' if n != 1 else ''}"
        if isinstance(value, dict):
            n = len(value)
            if n == 0:
                return "0 keys"
            keys = list(value.keys())[:max_items]
            preview = ", ".join(str(k) for k in keys)
            if n > max_items:
                return f"{{{preview}, …}} ({n} keys)"
            return f"{{{preview}}} ({n} keys)"
        return str(value)

    def _resolve_path(filepath: str):
        tokens = _tokenise(filepath)
        if not tokens:
            return None

        cur = _walk(payload_root, tokens)
        if cur is not None:
            if isinstance(cur, (dict, list)):
                return _summarise_collection(cur)
            return _format_scalar(cur)

        correlation_section = reasoning_section.get("correlation_analysis") if isinstance(reasoning_section, dict) else None
        if not isinstance(correlation_section, dict):
            correlation_section = {}
        routing_events_alias = None
        if isinstance(routing_section, dict):
            routing_events_alias = routing_section.get("routing_events") or routing_section.get("events")
            if routing_events_alias is None and isinstance(routing_section.get("hijack"), dict):
                routing_events_alias = routing_section["hijack"].get("origin_hijacked", [])
        timeline_alias = None
        if isinstance(traffic_section, dict):
            timeline_alias = traffic_section.get("timeline")
            if timeline_alias is None and isinstance(traffic_section.get("multi_scale_analysis"), dict):
                timeline_alias = (traffic_section["multi_scale_analysis"] or {}).get("timeline")
        uaw_value = None
        if isinstance(reasoning_section, dict) and reasoning_section.get("user_analysis_window"):
            uaw_value = reasoning_section.get("user_analysis_window")
        elif isinstance(traffic_section, dict) and traffic_section.get("user_analysis_window"):
            uaw_value = {"value": traffic_section.get("user_analysis_window")}
        target_as_alias = None
        if isinstance(reasoning_section, dict):
            target_as_alias = reasoning_section.get("target_as")
        if not target_as_alias and isinstance(traffic_section, dict):
            target_as_alias = traffic_section.get("target_as")
        if not target_as_alias and isinstance(routing_section, dict):
            target_as_alias = routing_section.get("target_as")

        aliases = {
            "classification": reasoning_section.get("classification") if isinstance(reasoning_section, dict) else None,
            "correlation_analysis": correlation_section,
            "hypotheses": reasoning_section.get("hypotheses") if isinstance(reasoning_section, dict) else None,
            "auto_probe_findings": reasoning_section.get("auto_probe_findings") if isinstance(reasoning_section, dict) else None,
            "evidence_chain": reasoning_section.get("evidence_chain") if isinstance(reasoning_section, dict) else None,
            "diagnosis": reasoning_section.get("diagnosis") if isinstance(reasoning_section, dict) else None,
            "user_analysis_window": uaw_value,
            "target_as": target_as_alias,
            "routing_events": routing_events_alias,
            "delta_ts": correlation_section.get("delta_ts") if isinstance(correlation_section, dict) else None,
            "timeline": timeline_alias,
        }
        if tokens[0] in aliases:
            cur = _walk(aliases[tokens[0]], tokens[1:])
            if cur is not None:
                if isinstance(cur, (dict, list)):
                    return _summarise_collection(cur)
                return _format_scalar(cur)

        for section in (traffic_section, routing_section, reasoning_section, taw_section):
            candidates = [section]
            if isinstance(section, dict):
                inner = section.get("result")
                if isinstance(inner, dict):
                    candidates.append(inner)
            for sec in candidates:
                cur = _walk(sec, tokens)
                if cur is not None and not isinstance(cur, (dict, list)):
                    return _format_scalar(cur)
                if cur is not None and isinstance(cur, (dict, list)):
                    return _summarise_collection(cur)
        return None

    bracket_re = re.compile(r"\[([A-Za-z_][\w.\[\]0-9]{1,200})\]")

    def _repl(m):
        path = m.group(1)
        val = _resolve_path(path)
        if val is None:
            return "(no data)"
        return val

    return bracket_re.sub(_repl, html)


def _format_scalar(value) -> str:
    """Format a scalar for display in the report HTML.

    Floats that are exactly integer-valued render as ``"100.0"`` (not
    ``"100"``) so round-trip equality with the structured payload holds
    for reviewer-facing diffs. Non-integer floats use ``%g`` so we don't
    show spurious trailing zeros. Strings and ints pass through.
    """
    if isinstance(value, float):
        if value.is_integer():
            return f"{value:.1f}"
        return f"{value:.4g}"
    if isinstance(value, bool):
        return str(value).lower()
    return str(value)
