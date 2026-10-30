#!/usr/bin/env python3
"""Find attribute accesses that resolve to nothing.

``self.x`` is a *call* of the attribute ``x``.  If the class defines
``x`` as a method, the call works; if the class defines ``x`` as an
instance attribute holding a callable, it also works.  The failure mode
this script catches is the third case: the class defines a *different*
name and something still calls ``self.x``, which fails at runtime with
``AttributeError`` -- and only on the code path that reaches it.

The script resolves each class's attribute set through its in-tree base
classes and reports every ``self.x`` / ``cls.x`` whose name is in
neither the class nor its bases.

Usage:
    python scripts/check_attribute_calls.py
"""
from __future__ import annotations

import ast
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ROOTS = ("agents", "detectors", "scripts", "tools", "llm", "data", "utils",
         "tests", "workflow_engine.py", "chief_agent.py", "config.py")


def source_files() -> list[Path]:
    out: list[Path] = []
    for root in ROOTS:
        p = PROJECT_ROOT / root
        if not p.exists():
            continue
        if p.is_file():
            out.append(p)
            continue
        out += [f for f in p.rglob("*.py") if "__pycache__" not in str(f)]
    return sorted(out)


def main() -> int:
    files = source_files()
    trees: dict[Path, ast.AST] = {}
    for p in files:
        try:
            trees[p] = ast.parse(p.read_text())
        except SyntaxError:
            continue

    own: dict[str, set[str]] = {}
    bases: dict[str, list[str]] = {}
    for p, t in trees.items():
        for node in ast.walk(t):
            if not isinstance(node, ast.ClassDef):
                continue
            names = own.setdefault(node.name, set())
            for sub in ast.walk(node):
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    names.add(sub.name)
                elif isinstance(sub, ast.AnnAssign) and isinstance(sub.target, ast.Name):
                    names.add(sub.target.id)
                elif isinstance(sub, ast.Assign):
                    for t2 in sub.targets:
                        if isinstance(t2, ast.Name):
                            names.add(t2.id)
                elif isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name) \
                        and sub.value.id in ("self", "cls"):
                    names.add(sub.attr)
            bases[node.name] = [b.id for b in node.bases if isinstance(b, ast.Name)]

    def resolve(cls: str, seen: set[str] | None = None) -> set[str]:
        seen = seen or set()
        if cls in seen:
            return set()
        seen.add(cls)
        out = set(own.get(cls, set()))
        for b in bases.get(cls, []):
            out |= resolve(b, seen)
        return out

    problems: list[tuple[Path, int, str, str]] = []
    for p, t in trees.items():
        for node in ast.walk(t):
            if not isinstance(node, ast.ClassDef):
                continue
            allowed = resolve(node.name)
            for sub in ast.walk(node):
                if not isinstance(sub, ast.Attribute):
                    continue
                if not (isinstance(sub.value, ast.Name)
                        and sub.value.id in ("self", "cls")):
                    continue
                if sub.attr in allowed:
                    continue
                problems.append((p, sub.lineno, node.name, sub.attr))

    if not problems:
        print("every self/cls attribute access resolves")
        return 0
    print(f"{len(problems)} unresolved self/cls attribute access(es):")
    for p, line, cls, attr in problems:
        print(f"  {p.relative_to(PROJECT_ROOT)}:{line}  {cls}.{attr}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
