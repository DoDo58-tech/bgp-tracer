import json
from datetime import datetime
from pathlib import Path
from typing import Optional


def make_json_safe(value, _seen=None):
    try:
        if _seen is None:
            _seen = set()
        obj_id = id(value)
        if obj_id in _seen:
            return f"<circular:{type(value).__name__}>"
        _seen.add(obj_id)
        try:
            if value is None:
                return None
            if isinstance(value, (str, int, float, bool)):
                return value
            if isinstance(value, set):
                return sorted([make_json_safe(v, _seen) for v in value])
            if isinstance(value, (list, tuple)):
                return [make_json_safe(v, _seen) for v in value]
            if isinstance(value, dict):
                return {str(k): make_json_safe(v, _seen) for k, v in value.items()}
            if isinstance(value, datetime):
                return value.isoformat()
            if isinstance(value, Path):
                return str(value)
            return str(value)
        finally:
            _seen.discard(obj_id)
    except Exception:
        return str(value)


def extract_json_object(content):
    """Return the first balanced ``{...}`` substring from ``content`` or ``None``.

    Walks ``content`` from the first ``{`` it sees and tracks brace depth, so
    a nested ``{...}`` inside a string value or comment cannot trick the parser
    into truncating the JSON early.
    """
    if not content:
        return None
    start = content.find("{")
    while start != -1:
        depth = 0
        in_str = False
        escape = False
        for i in range(start, len(content)):
            ch = content[i]
            if in_str:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
                continue
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return content[start:i + 1]
        start = content.find("{", start + 1)
    return None


def parse_llm_json(raw_text):
    """Parse JSON from raw LLM output, tolerating stray prose/markdown.

    Tries (in order):
      1. Strict parse of the trimmed text.
      2. JSON fenced by ``\\u0060\\u0060\\u0060json ... \\u0060\\u0060\\u0060``.
      3. The first balanced ``{...}`` substring (handles nested objects and
         braces that appear inside string values).

    Raises :class:`json.JSONDecodeError` if none of the above succeed.
    """
    if raw_text is None:
        raise ValueError("Empty LLM response")
    raw = str(raw_text).strip()
    if not raw:
        raise ValueError("Empty LLM response")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass

    # Markdown code fence: ```json ... ```
    import re as _re
    for m in _re.finditer(r"```(?:json)?\s*\n?(.*?)\n?```", raw, _re.DOTALL):
        candidate = m.group(1).strip()
        if not candidate or "{" not in candidate:
            continue
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue

    snippet = extract_json_object(raw)
    if snippet is not None:
        try:
            return json.loads(snippet)
        except json.JSONDecodeError:
            pass
    raise json.JSONDecodeError("Unable to locate balanced JSON object in LLM output", raw, 0)
