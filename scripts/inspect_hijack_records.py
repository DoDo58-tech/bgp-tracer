"""Summarise a hijack detector's record list without loading the whole cache.

The hijack detector emits one record per announcement, so a busy window can
hold hundreds of thousands of records and make the cache hundreds of
megabytes.  This tool extracts just the record list of one section and
reports its shape: how many records, how many distinct prefixes and origins,
and how much of the list is re-announcement of the same incident.

Usage:
    python3 scripts/inspect_hijack_records.py <cache.json> [section]
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

DEFAULT_SECTIONS = ("origin_hijacked", "forge_hijacked",
                     "origin_hijacking", "forge_hijacking")


def extract_list(path: Path, section: str) -> list:
    """Pull one top-level list out of the cache without parsing the rest."""
    text = path.read_text(encoding="utf-8", errors="ignore")
    marker = f'"{section}"'
    idx = text.find(marker)
    if idx < 0:
        raise KeyError(f"{section} not found in {path.name}")
    start = text.find("[", idx)
    if start < 0:
        raise KeyError(f"{section} is not a list")
    depth = 0
    in_string = False
    escaped = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
            if depth == 0:
                return json.loads(text[start:i + 1])
    raise ValueError("unterminated list")


def summarise(records: list) -> None:
    print(f"   records: {len(records)}")
    if not records:
        return
    print(f"   record keys: {list(records[0].keys())}")
    prefixes = Counter()
    origins = Counter()
    pairs = Counter()
    for rec in records:
        prefix = rec.get("prefix") or rec.get("prefix_str") or "?"
        origin = (rec.get("hijacking_as") or rec.get("origin_as")
                  or rec.get("hijacker_as") or "?")
        prefixes[prefix] += 1
        origins[origin] += 1
        pairs[(origin, prefix)] += 1
    print(f"   distinct prefixes: {len(prefixes)}")
    print(f"   distinct origins : {len(origins)}")
    print(f"   distinct (origin, prefix) incidents: {len(pairs)}")
    if prefixes:
        top = prefixes.most_common(3)
        print(f"   top prefixes: {top}")
        print(f"   max re-announcements of one prefix: {top[0][1]}")
    if origins:
        print(f"   top origins: {origins.most_common(3)}")


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    path = Path(sys.argv[1])
    sections = (sys.argv[2:] or list(DEFAULT_SECTIONS))
    print(f"=== {path.name}")
    for section in sections:
        try:
            records = extract_list(path, section)
        except (KeyError, ValueError) as exc:
            print(f"   {section}: {exc}")
            continue
        print(f" -- {section}")
        summarise(records)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
