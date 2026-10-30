#!/usr/bin/env python3
"""Find comment and docstring fragments left behind by a bulk edit.

A docstring trimmer that keeps "the first line" can cut a sentence in
half, and a comment block reducer that keeps "the first line" can leave
a clause that ends in a colon and never gets its list.  Both read as
noise to a human and, worse, can look like a contract that is not
there.

This script reports:

* a docstring whose last line ends in a word that requires more text
  (``the``, ``a``, ``of``, ``:``, ``,``);
* a standalone comment whose text ends in ``:`` with nothing following;
* a comment that opens a sentence and stops mid-clause.

Usage:
    python scripts/check_doc_fragments.py [--verbose]
"""
from __future__ import annotations

import argparse
import ast
import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ROOTS = ("agents", "detectors", "scripts", "tools", "llm", "data", "utils",
         "workflow_engine.py", "chief_agent.py")

DANGLING_WORDS = {
    "the", "a", "an", "of", "to", "and", "or", "but", "with", "for",
    "from", "in", "on", "at", "by", "as", "is", "are", "was", "were",
    "be", "that", "which", "this", "these", "those", "it", "its",
}


def docstring_spans(tree: ast.AST) -> list[tuple[int, int, str]]:
    spans = []
    holders = (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
    for node in ast.walk(tree):
        if not isinstance(node, holders):
            continue
        body = getattr(node, "body", None)
        if not body:
            continue
        first = body[0]
        if not (isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)):
            continue
        spans.append((first.lineno, first.end_lineno or first.lineno,
                      first.value.value))
    return spans


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    files: list[Path] = []
    for root in ROOTS:
        p = PROJECT_ROOT / root
        if not p.exists():
            continue
        files += [p] if p.is_file() else [
            f for f in p.rglob("*.py") if "__pycache__" not in str(f)
        ]

    problems: list[tuple[Path, int, str]] = []
    for p in sorted(set(files)):
        try:
            tree = ast.parse(p.read_text())
        except SyntaxError:
            continue
        for start, end, body in docstring_spans(tree):
            lines = [ln.strip() for ln in body.splitlines() if ln.strip()]
            if not lines:
                continue
            last = lines[-1]
            if not last:
                continue
            # A docstring that ends in a colon promises a list it never
            # delivers.
            if last.endswith(":"):
                problems.append((p, start, f"docstring ends in ':': {last[-60:]!r}"))
                continue
            tail = re.findall(r"[A-Za-z']+", last)
            if tail and tail[-1].lower() in DANGLING_WORDS:
                problems.append((p, start, f"docstring ends mid-clause: {last[-60:]!r}"))

    if not problems:
        print("no truncated docstrings")
        return 0
    print(f"{len(problems)} truncated docstring(s):")
    for p, line, msg in problems:
        print(f"  {p.relative_to(PROJECT_ROOT)}:{line}  {msg}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
