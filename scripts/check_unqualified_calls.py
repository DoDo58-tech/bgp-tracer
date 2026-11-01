#!/usr/bin/env python3
"""Find calls to a name that only exists as a method or nested function.

``derive_verdict(context)`` parsed fine and imported fine, but raised
``NameError`` the first time the code path ran, because ``derive_verdict``
is a static method on the enclosing class and must be reached as
``self.derive_verdict``.  The same shape of bug hides a call to a
*module-level* function that was actually defined as a nested helper.

This script builds the set of names that are defined at module level
(imports, top-level defs, top-level assignments) and reports every
``Name(...)`` call whose name is **not** in that set, is not a builtin,
and **is** defined as a method or nested function somewhere in the same
file.  Those calls resolve to nothing on the path that executes them.

Usage:
    python scripts/check_unqualified_calls.py
"""
from __future__ import annotations

import ast
import builtins
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ROOTS = ("agents", "detectors", "scripts", "tools", "llm", "data", "utils",
         "workflow_engine.py", "chief_agent.py")

BUILTINS = set(dir(builtins))


def module_scope_names(tree: ast.Module):
    """Every name bound at module level, including inside try/if blocks."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for a in node.names:
                names.add(a.asname or a.name.split(".")[0])
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    names.add(t.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
    return names


def inner_defs(tree: ast.Module):
    """Names defined anywhere as a function or method (any depth)."""
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.add(node.name)
    return out


def main():
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
        top = module_scope_names(tree)
        inner = inner_defs(tree)
        # Only the names that exist as inner defs but NOT at module level
        # are candidates: a call to one of them from module scope (or
        # from a plain function body) resolves to nothing.
        suspects = inner - top
        if not suspects:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Name):
                continue
            name = node.func.id
            if name in top or name in BUILTINS or name not in suspects:
                continue
            problems.append((p, node.lineno, name))

    if not problems:
        print("no unqualified call to a method/nested-only name")
        return 0
    print(f"{len(problems)} unqualified call(s) that resolve to nothing:")
    for p, line, name in problems:
        print(f"  {p.relative_to(PROJECT_ROOT)}:{line}  {name}(...)")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
