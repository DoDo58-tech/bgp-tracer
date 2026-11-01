#!/usr/bin/env python3
"""Find calls to *imported* functions whose argument count cannot match.

Companion to ``check_call_arity.py``: that one only checks functions
defined in the same file.  This one resolves ``from mod import name``
(and ``from pkg.mod import name``) to the module's source, reads the
signature, and checks every call to ``name(...)`` in the importing file.

Only handles the flat import forms the project uses; aliased and
``import mod`` + ``mod.fn()`` forms are skipped rather than guessed.

Usage:
    python scripts/check_import_arity.py
"""
from __future__ import annotations

import ast
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ROOTS = ("agents", "detectors", "scripts", "tools", "llm", "data", "utils")
TOP_FILES = ("workflow_engine.py", "chief_agent.py")


def resolve_module(mod: str):
    rel = mod.replace(".", "/")
    for cand in (PROJECT_ROOT / f"{rel}.py", PROJECT_ROOT / rel / "__init__.py"):
        if cand.exists():
            return cand
    return None


def arity_of(fn: ast.FunctionDef | ast.AsyncFunctionDef):
    a = fn.args
    n_pos = len(a.posonlyargs) + len(a.args)
    n_req = n_pos - len(a.defaults)
    return n_req, n_pos, a.vararg is not None


def main():
    files: list[Path] = []
    for root in ROOTS:
        p = PROJECT_ROOT / root
        if p.exists():
            files += [f for f in p.rglob("*.py") if "__pycache__" not in str(f)]
    for tf in TOP_FILES:
        p = PROJECT_ROOT / tf
        if p.exists():
            files.append(p)

    # cache module -> {name: (req,pos,vararg)}
    sig_cache: dict[Path, dict[str, tuple]] = {}

    def sigs_for(path: Path):
        if path in sig_cache:
            return sig_cache[path]
        out = {}
        try:
            tree = ast.parse(path.read_text())
        except SyntaxError:
            sig_cache[path] = out
            return out
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                out[node.name] = arity_of(node)
        sig_cache[path] = out
        return out

    problems = []
    for p in sorted(set(files)):
        try:
            tree = ast.parse(p.read_text())
        except SyntaxError:
            continue
        imported: dict[str, tuple] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                tgt = resolve_module(node.module)
                if tgt is None:
                    continue
                sigs = sigs_for(tgt)
                for a in node.names:
                    if a.name in sigs:
                        imported[a.asname or a.name] = sigs[a.name]
        if not imported:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            if not isinstance(f, ast.Name) or f.id not in imported:
                continue
            n_req, n_pos, vararg = imported[f.id]
            if vararg or any(isinstance(a, ast.Starred) for a in node.args):
                continue
            if any(k.arg is None for k in node.keywords):
                continue
            n_args = len(node.args)
            n_kw = len(node.keywords)
            if n_args > n_pos:
                problems.append((p, node.lineno, f.id, n_args, n_kw, n_req, n_pos, "too many"))
            elif n_args + n_kw < n_req:
                problems.append((p, node.lineno, f.id, n_args, n_kw, n_req, n_pos, "too few"))

    if not problems:
        print("no cross-module arity mismatch")
        return 0
    print(f"{len(problems)} cross-module arity mismatch(es):")
    for p, line, name, na, nk, nreq, npos, kind in problems:
        print(f"  {p.relative_to(PROJECT_ROOT)}:{line}  {name}() "
              f"called {na}+{nk}kw ({kind}); needs {nreq}..{npos}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
