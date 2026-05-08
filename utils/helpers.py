import json
from datetime import datetime
from pathlib import Path


def make_json_safe(value):
    try:
        if value is None:
            return None
        if isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, set):
            return sorted([make_json_safe(v) for v in value])
        if isinstance(value, (list, tuple)):
            return [make_json_safe(v) for v in value]
        if isinstance(value, dict):
            return {str(k): make_json_safe(v) for k, v in value.items()}
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, Path):
            return str(value)
        return str(value)
    except Exception:
        return str(value)


def parse_llm_json(raw_text):
    if not raw_text:
        raise ValueError("Empty LLM response")
    raw = raw_text.strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        start = raw.find("{")
        end = raw.rfind("}")
        if start != -1 and end != -1 and end > start:
            snippet = raw[start : end + 1]
            return json.loads(snippet)
        raise
