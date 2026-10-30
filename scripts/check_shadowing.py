#!/usr/bin/env python3
"""Find local names that shadow a module-level function.

``x = x(...)`` inside a function is legal Python only when the
right-hand ``x`` is resolved *before* the assignment makes ``x`` local
-- which it is not: the assignment makes ``x`` local for the whole
scope, so the right-hand side raises ``UnboundLocalError`` at runtime.

The pattern is easy to introduce during a bulk rename, when a function
``foo`` and a local variable ``foo`` end up with the same name.  It
parses cleanly and only fails on the code path that runs it.

This script reports every assignment whose target name is also a
module-level function in the same file.

Usage:
    python scripts/check_shadowing.py
"""
from __future__ import annotations

import ast
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ROOTS = ("agents", "detectors", "scripts", "tools", "llm", "data", "utils",
         "tests", "workflow_engine.py", "chief_agent.py")


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
        module_names = {
            n.name for n in tree.body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        if not module_names:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for sub in ast.walk(node):
                targets: list[str] = []
                if isinstance(sub, ast.Assign):
                    targets = [t.id for t in sub.targets if isinstance(t, ast.Name)]
                elif isinstance(sub, ast.AnnAssign) and isinstance(sub.target, ast.Name):
                    targets = [sub.target.id]
                elif isinstance(sub, ast.AugAssign) and isinstance(sub.target, ast.Name):
                    targets = [sub.target.id]
                for name in targets:
                    if name in module_names:
                        problems.append((p, sub.lineno, name, node.name))

    if not problems:
        print("no local name shadows a module-level function")
        return 0
    print(f"{len(problems)} shadowing assignment(s):")
    for p, line, name, fn in problems:
        print(f"  {p.relative_to(PROJECT_ROOT)}:{line}  "
              f"'{name}' shadows the module function, assigned inside {fn}()")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
