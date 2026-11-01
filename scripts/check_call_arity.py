#!/usr/bin/env python3
"""Find calls whose argument count cannot match the callee's signature.

The underscore-rename refactor changed several function *signatures*
(e.g. ``slim_section(data)`` became ``slim_section(section, data)``) and
some call sites were never updated.  These parse and import fine and
fail only at runtime, so a static arity check is the cheap way to catch
them before an experiment burns an hour.

Scope: calls to a bare ``Name(...)`` where the name is bound at module
level in the *same file* to a function defined in that file.  That
covers the intra-module cases the refactor actually broke; cross-module
calls are checked by the same logic keyed on import, but only report
when the callee and caller are the same file (to avoid false positives
from re-exports).

Usage:
    python scripts/check_call_arity.py
"""
from __future__ import annotations

import ast
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ROOTS = ("agents", "detectors", "scripts", "tools", "llm", "data", "utils",
         "workflow_engine.py", "chief_agent.py")


def func_arity(node: ast.FunctionDef | ast.AsyncFunctionDef):
    a = node.args
    n_pos = len(a.posonlyargs) + len(a.args)
    n_required = n_pos - len(a.defaults)
    has_vararg = a.vararg is not None
    has_kwarg = a.kwonlyargs
    # kw-only args without defaults can't be filled positionally
    kw_required = sum(
        1 for d, kw in zip(a.kw_defaults, a.kwonlyargs) if d is None
    ) if has_kwarg else 0
    return n_required, n_pos, has_vararg, kw_required


def main():
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
        # module-level function defs only
        defs: dict[str, tuple] = {}
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                defs[node.name] = func_arity(node)
        if not defs:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            if not isinstance(f, ast.Name) or f.id not in defs:
                continue
            n_req, n_pos, has_vararg, kw_req = defs[f.id]
            n_args = len(node.args)
            has_star = any(isinstance(a, ast.Starred) for a in node.args)
            if has_star or has_vararg:
                continue
            n_kw = len(node.keywords)
            has_dstar = any(k.arg is None for k in node.keywords)
            if has_dstar:
                continue
            if n_args < n_req or n_args > n_pos:
                # allow if some positional slots are covered by kwargs
                missing = max(0, n_req - n_args - n_kw)
                extra = max(0, n_args - n_pos)
                if missing == 0 and extra == 0:
                    continue
                problems.append((p, node.lineno, f.id, n_args, n_kw, n_req, n_pos))

    if not problems:
        print("no intra-module arity mismatch")
        return 0
    print(f"{len(problems)} intra-module arity mismatch(es):")
    for p, line, name, na, nk, nreq, npos in problems:
        print(f"  {p.relative_to(PROJECT_ROOT)}:{line}  {name}() "
              f"called with {na} positional + {nk} kw; "
              f"needs {nreq}..{npos}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
