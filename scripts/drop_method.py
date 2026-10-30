#!/usr/bin/env python3
"""Delete a named method from a Python file by AST span.

Usage:
    python scripts/drop_method.py <file> <Class.method> [...]

Each method is removed together with the blank lines that separated it,
so the file stays tidy.  The result is re-parsed before it is written.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path


def find_span(tree: ast.AST, qualname: str) -> tuple[int, int] | None:
    cls_name, _, member = qualname.partition(".")
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef) or node.name != cls_name:
            continue
        for child in node.body:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                    and child.name == member:
                return child.lineno, child.end_lineno
    return None


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    path = Path(sys.argv[1])
    targets = sys.argv[2:]
    source = path.read_text()
    tree = ast.parse(source)
    lines = source.splitlines()

    spans = []
    for qual in targets:
        span = find_span(tree, qual)
        if span is None:
            print(f"  NOT FOUND: {qual}")
            continue
        spans.append(span)
        print(f"  removing {qual} (lines {span[0]}-{span[1]})")

    for start, end in sorted(spans, reverse=True):
        begin = start - 1
        while begin > 0 and lines[begin - 1].strip() == "":
            begin -= 1
        finish = end
        while finish < len(lines) and lines[finish].strip() == "":
            finish += 1
        del lines[begin:finish]

    new = "\n".join(lines) + "\n"
    ast.parse(new)
    path.write_text(new)
    print(f"  -> {path} rewritten")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
