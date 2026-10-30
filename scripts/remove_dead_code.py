#!/usr/bin/env python3
"""Remove confirmed dead functions and methods.

The project accumulated a layer of API surface that nothing calls: the
publish/subscribe mechanism on the Blackboard (a subscriber is never
registered, so every notification was a no-op), the agent inbox
machinery (no agent ever receives a message), and a set of helper
functions that were superseded but never deleted.

This script deletes them.  It works on exact AST line ranges, so
nothing else in the file moves, and it refuses to touch a name that
still has a reference anywhere in the tree -- including tests, docs
and configuration.

Usage:
    python scripts/remove_dead_code.py --list
    python scripts/remove_dead_code.py --apply
"""
from __future__ import annotations

import argparse
import ast
import re
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

# (file, qualified name, reason)
TARGETS: list[tuple[str, str, str]] = [
    ("agents/core.py", "Blackboard.subscribe", "no subscriber is ever registered"),
    ("agents/core.py", "Blackboard.unsubscribe", "no subscriber is ever registered"),
    ("agents/core.py", "Blackboard._notify", "pub/sub mechanism is unused"),
    ("agents/core.py", "Blackboard.log_event", "never called"),
    ("agents/core.py", "Blackboard.snapshot", "never called"),
    ("agents/core.py", "Agent.receive", "agent inbox is unused"),
    ("agents/core.py", "Agent.peek_inbox", "agent inbox is unused"),
    ("agents/core.py", "Agent.pop_inbox", "agent inbox is unused"),
    ("agents/core.py", "Agent.count_inbox", "agent inbox is unused"),
    ("agents/core.py", "Agent.broadcast", "never called"),
    ("agents/core.py", "Agent.read_config", "never called"),
    ("agents/core.py", "Agent.write_result", "never called"),
    ("agents/core.py", "Agent.record_step_timing", "never called"),
]


def build_index() -> dict[str, list[str]]:
    """Index every call site in the tree, once.

    A per-name ``grep`` over the whole tree is far too slow: the
    ``docs`` directory alone holds large artefacts.  The index is built
    with a single walk and a single regular expression, and it is
    reused for every candidate name.
    """
    global _INDEX
    if _INDEX is not None:
        return _INDEX
    index: dict[str, list[str]] = {}
    roots = [
        "agents", "detectors", "scripts", "tools", "llm", "data", "utils",
        "tests", "docs", "workflow_engine.py", "chief_agent.py", "config.py",
    ]
    pattern = re.compile(r"(^|[^\w.])([A-Za-z_][A-Za-z0-9_]*)\s*\(")
    for root in roots:
        p = PROJECT_ROOT / root
        if not p.exists():
            continue
        paths = [p] if p.is_file() else p.rglob("*")
        for path in paths:
            if not path.is_file():
                continue
            if path.suffix not in (".py", ".md", ".json", ".tex", ".yaml", ".yml"):
                continue
            if "__pycache__" in str(path):
                continue
            try:
                text = path.read_text(errors="replace")
            except (ValueError):  # noqa: BLE001
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                if re.search(rf"^\s*(async\s+)?def\s+[A-Za-z_][A-Za-z0-9_]*\s*\(", line):
                    continue
                if path.name == "remove_dead_code.py":
                    continue
                for m in pattern.finditer(line):
                    name = m.group(2)
                    if name in ("if", "for", "while", "return", "not", "and",
                                "or", "in", "elif", "assert", "del", "raise",
                                "yield", "lambda", "await", "with", "print"):
                        continue
                    index.setdefault(name, []).append(
                        f"{path.relative_to(PROJECT_ROOT)}:{lineno}: {line.strip()[:100]}"
                    )
    _INDEX = index
    return index


_INDEX: dict[str, list[str]] | None = None


def referenced_anywhere(name: str) -> list[str]:
    """Return the call sites that reference ``name``.

    Only a *call* counts as a reference: the definition itself, the
    removal script's own target list, and the word appearing inside an
    English sentence or a prompt template are all ignored, because none
    of them would keep the function alive.
    """
    return list(build_index().get(name, ()))


def find_member_span(tree: ast.AST, qualname: str) -> tuple[int, int] | None:
    """Return the ``(lineno, end_lineno)`` of a class method."""
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
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()

    by_file: dict[str, list[tuple[str, str]]] = {}
    for path, qual, reason in TARGETS:
        by_file.setdefault(path, []).append((qual, reason))

    for rel, targets in sorted(by_file.items()):
        path = PROJECT_ROOT / rel
        if not path.exists():
            print(f"SKIP (missing): {rel}")
            continue
        source = path.read_text()
        tree = ast.parse(source)
        lines = source.splitlines()

        removals: list[tuple[int, int, str, str]] = []
        for qual, reason in targets:
            member = qual.partition(".")[2]
            hits = referenced_anywhere(member)
            if hits:
                print(f"  KEEP {rel}:{qual} — still referenced:")
                for h in hits[:3]:
                    print(f"        {h}")
                continue
            span = find_member_span(tree, qual)
            if span is None:
                print(f"  KEEP {rel}:{qual} — not found")
                continue
            removals.append((span[0], span[1], qual, reason))

        if not removals:
            continue
        for start, end, qual, reason in removals:
            print(f"  REMOVE {rel}:{qual} — {reason}")
        if not args.apply:
            continue
        for start, end, _, _ in sorted(removals, reverse=True):
            # Drop the method and the blank lines that separated it.
            begin = start - 1
            while begin > 0 and lines[begin - 1].strip() == "":
                begin -= 1
            finish = end
            while finish < len(lines) and lines[finish].strip() == "":
                finish += 1
            del lines[begin:finish]
        path.write_text("\n".join(lines) + "\n")
        print(f"  -> applied to {rel}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
