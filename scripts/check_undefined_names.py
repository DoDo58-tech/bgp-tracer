#!/usr/bin/env python3
"""Find calls to an undefined underscore-prefixed name whose stripped twin exists.

The underscore-strip refactor renamed ``_to_canonical_severity`` to
``to_canonical_severity`` and ``_runner`` to ``run_probe`` but left some
call sites untouched.  ``check_unqualified_calls.py`` covers calls to
*methods/nested* defs; this covers the complementary shape — a bare
``Name(...)`` that is **never bound anywhere** in the file, while its
``lstrip('_')`` form *is* bound (imported or defined).

A third shape is reported too: a bare ``Name`` read (not just called)
that is unbound but whose stripped form is bound.

Usage:
    python scripts/check_undefined_names.py
"""
from __future__ import annotations

import ast
import builtins
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ROOTS = ("agents", "detectors", "scripts", "tools", "llm", "data", "utils",
         "workflow_engine.py", "chief_agent.py")
BUILTINS = set(dir(builtins))


def bound_names(tree: ast.Module) -> set[str]:
    """Every name bound anywhere in the module (module scope, imports,
    function args, locals, comprehension targets, except-as, defs)."""
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                out.add(a.asname or a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for a in node.names:
                out.add(a.asname or a.name)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(node.name)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            out.add(node.id)
        elif isinstance(node, ast.arg):
            out.add(node.arg)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            out.add(node.name)
        elif isinstance(node, ast.Global):
            out.update(node.names)
    return out


def main() -> int:
    files: list[Path] = []
    for root in ROOTS:
        p = PROJECT_ROOT / root
        if not p.exists():
            continue
        files += [p] if p.is_file() else [
            f for f in p.rglob("*.py") if "__pycache__" not in str(f)
        ]

    problems = []
    for p in sorted(set(files)):
        try:
            tree = ast.parse(p.read_text())
        except SyntaxError:
            continue
        bound = bound_names(tree)
        for node in ast.walk(tree):
            # only report *live* uses (loads), not stores
            if not isinstance(node, ast.Name) or not isinstance(node.ctx, ast.Load):
                continue
            name = node.id
            if name in bound or name in BUILTINS:
                continue
            stripped = name.lstrip("_")
            if not name.startswith("_") or stripped == name:
                continue
            if stripped in bound:
                problems.append((p, node.lineno, name, stripped))

    if not problems:
        print("no undefined underscore-prefixed names with a bound twin")
        return 0

    # de-dup per (file, name) keeping first line
    seen = {}
    for p, line, name, stripped in problems:
        key = (str(p), name, stripped)
        if key not in seen:
            seen[key] = line
    print(f"{len(seen)} undefined underscore name(s) with a bound stripped twin:")
    for (fp, name, stripped), line in sorted(seen.items()):
        rel = Path(fp).relative_to(PROJECT_ROOT)
        print(f"  {rel}:{line}  {name}  -> {stripped}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
