"""Stream a quick cache and report the size of each section.

The largest caches reach several hundred megabytes because the hijack
detector writes one record per announcement.  Loading such a file with
``json.load`` is slow and memory-hungry, so this tool walks the file with a
incremental scanner and never materialises the whole document.

Usage:
    python3 scripts/inspect_cache_size.py results/quick/quick_*.json
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path


def top_level_spans(text: str) -> list[tuple[str, int, int]]:
    """Return (key, start, end) offsets of each top-level object member.

    A tiny hand-rolled scanner is used instead of a JSON parser so that the
    file is read once, sequentially, without building any Python object for
    the values themselves.
    """
    spans: list[tuple[str, int, int]] = []
    depth = 0
    in_string = False
    escaped = False
    key_start = -1
    current_key = ""
    value_start = 0
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
                if depth == 1 and key_start >= 0:
                    current_key = text[key_start:i]
                    key_start = -1
        else:
            if ch == '"':
                in_string = True
                if depth == 1:
                    key_start = i + 1
            elif ch in "{[":
                if depth == 1 and key_start < 0:
                    # value begins with a container
                    value_start = i
                    depth += 1
                    if current_key:
                        spans.append((current_key, value_start, -1))
                        current_key = ""
                else:
                    depth += 1
            elif ch in "}]":
                depth -= 1
                if depth == 1:
                    for idx in range(len(spans) - 1, -1, -1):
                        if spans[idx][2] == -1:
                            spans[idx] = (spans[idx][0], spans[idx][1], i + 1)
                            break
            elif ch == "," and depth == 1:
                current_key = ""
            elif ch == ":" and depth == 1:
                value_start = i + 1
                key_start = -1
                if current_key:
                    spans.append((current_key, value_start, -1))
                    current_key = ""
        i += 1
    return spans


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    for arg in sys.argv[1:]:
        path = Path(arg)
        text = path.read_text(encoding="utf-8", errors="ignore")
        spans = top_level_spans(text)
        print(f"\n=== {path.name}  ({len(text)/1e6:.1f} MB)")
        for key, start, end in spans:
            size = (end - start) if end > start else 0
            print(f"   {key:28s} {size/1e6:9.2f} MB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
