#!/usr/bin/env python3
"""Find properties whose body re-enters the property itself.

A property ``foo`` backed by a field ``_foo`` is a common pattern.  A
bulk rename that strips the leading underscore from *both* the property
and the field turns ``self._foo`` inside the getter into ``self.foo``,
which calls the getter again -- infinite recursion, reported only at
runtime as ``RecursionError``.

This script reports every property getter whose body reads the same
name it defines, which is always a bug: a getter that wants its own
value would recurse.

Usage:
    python scripts/check_property_recursion.py
"""
from __future__ import annotations

import ast
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ROOTS = ("agents", "detectors", "scripts", "tools", "llm", "data", "utils",
         "workflow_engine.py", "chief_agent.py")


def main() -> int:
    files: list[Path] = []
    for root in ROOTS:
        p = PROJECT_ROOT / root
        if not p.exists():
            continue
        files += [p] if p.is_file() else [
            f for f in p.rglob("*.py") if "__pycache__" not in str(f)
        ]

    problems: list[tuple[Path, int, str, str]] = []
    for p in sorted(set(files)):
        try:
            tree = ast.parse(p.read_text())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            for sub in node.body:
                if not isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                is_property = any(
                    (isinstance(d, ast.Name) and d.id == "property")
                    or (isinstance(d, ast.Attribute) and d.attr in ("setter", "getter"))
                    for d in sub.decorator_list
                )
                if not is_property:
                    continue
                for inner in ast.walk(sub):
                    if not isinstance(inner, ast.Attribute):
                        continue
                    if not (isinstance(inner.value, ast.Name)
                            and inner.value.id in ("self", "cls")):
                        continue
                    if inner.attr != sub.name:
                        continue
                    # A write is fine (it is the setter path); a read of
                    # the property from inside its own getter recurses.
                    if isinstance(inner.ctx, ast.Load):
                        problems.append((p, inner.lineno, node.name, sub.name))
                        break

    if not problems:
        print("no property recurses into itself")
        return 0
    print(f"{len(problems)} self-recursive property access(es):")
    for p, line, cls, name in problems:
        print(f"  {p.relative_to(PROJECT_ROOT)}:{line}  "
              f"{cls}.{name} reads self.{name} inside its own getter")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
