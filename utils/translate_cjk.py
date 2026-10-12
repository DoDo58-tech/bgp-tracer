"""Strip CJK characters from docstrings (multi-line strings).

Strategy:
  1. Find triple-quoted strings.
  2. Within each, drop CJK characters and full-width punctuation.
  3. Preserve indentation and quote style.

This is safer than line-by-line rewriting because docstring content is
never code, so we cannot break syntax by removing CJK characters from
it.  We do NOT touch single-line comments or string literals in code
paths (those may be load-bearing data, e.g. the CJK markers used by the
language detector in chief_agent.py).

Run:
    python3 -m utils.translate_cjk
"""
from __future__ import annotations
import re
from pathlib import Path

FILES = [
    "agents/token_budget.py",
    "agents/llm_reasoning.py",
    "agents/correlation_analyzer.py",
    "agents/hypothesis_manager.py",
    "agents/react_agent.py",
    "agents/reasoning_agent.py",
    "agents/investigation_supervisor.py",
    "agents/auto_probe_executor.py",
    "agents/impl/traffic_impl.py",
    "agents/report_agent.py",
    "detectors/unified_result.py",
    "detectors/evidence_chain_builder.py",
    "detectors/input_validation.py",
    "detectors/traffic/combined.py",
    "detectors/traffic/multi_scale_baseline.py",
    "detectors/traffic/traffic_detector.py",
    "detectors/traffic/detectors.py",
    "detectors/traffic/traffic_plotting.py",
    "detectors/outage/extract_event_features.py",
    "tools/tool_implementations.py",
]

PUNCT = {
    "\u3001": " ", "\u3002": ". ", "\uff0c": ", ", "\uff1a": ": ",
    "\uff1b": "; ", "\uff08": "(", "\uff09": ")", "\u300a": "<",
    "\u300b": ">", "\u3010": "[", "\u3011": "]", "\u300c": '"',
    "\u300d": '"', "\u300e": '"', "\u300f": '"', "\uff1f": "?",
    "\uff01": "!", "\u2014": "-", "\u2026": "...", "\u00b7": " ",
    "\u2022": "*", "\u25cf": "*", "\u25cb": "*", "\u201c": '"',
    "\u201d": '"', "\u2018": "'", "\u2019": "'", "\uff5e": "~",
    "\u3000": " ",
}

PUNCT_RE = re.compile("|".join(re.escape(k) for k in PUNCT))
IDEOR_RE = re.compile(r"[\u4e00-\u9fff]+")
WS_RE = re.compile(r"  +")


def _clean(content: str) -> str:
    out = PUNCT_RE.sub(lambda m: PUNCT[m.group(0)], content)
    out = IDEOR_RE.sub("", out)
    out = WS_RE.sub(" ", out)
    return out


def _process_docstring(content: str) -> str:
    """Find every triple-quoted string in `content` and strip CJK within it."""
    # We process one triple at a time using a simple state machine to avoid
    # touching string literals in code (which may be load-bearing data).
    out = []
    i = 0
    n = len(content)
    triple_dq = '"""'
    triple_sq = "'''"
    while i < n:
        if content[i:i + 3] == triple_dq:
            # Find the matching closing triple.
            j = content.find(triple_dq, i + 3)
            if j < 0:
                out.append(text[i:])
                break
            chunk = text[i:j + 3]
            # Only rewrite if the chunk actually has CJK or full-width
            # punctuation; otherwise leave the docstring alone (it is
            # already pure ASCII and may have intentional indentation).
            if IDEOR_RE.search(chunk) or PUNCT_RE.search(chunk):
                out.append(_clean(chunk))
            else:
                out.append(chunk)
            i = j + 3
            continue
        if content[i:i + 3] == triple_sq:
            j = content.find(triple_sq, i + 3)
            if j < 0:
                out.append(content[i:])
                break
            chunk = content[i:j + 3]
            if IDEOR_RE.search(chunk) or PUNCT_RE.search(chunk):
                out.append(_clean(chunk))
            else:
                out.append(chunk)
            i = j + 3
            continue
        out.append(content[i])
        i += 1
    return "".join(out)


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    rewritten = 0
    for rel in FILES:
        p = root / rel
        if not p.exists():
            print(f"  missing: {rel}")
            continue
        text = p.read_text(encoding="utf-8")
        new = _process_docstring(text)
        if new != text:
            p.write_text(new, encoding="utf-8")
            rewritten += 1
            print(f"  rewrote: {rel}")
    print(f"Total files rewritten: {rewritten}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
