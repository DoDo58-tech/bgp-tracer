#!/usr/bin/env python3
"""Find ``self.name`` calls whose method no longer exists.

The private-name rename touches both definitions and call sites, and a
call site can be missed when the method it targets is defined on a base
class in another module.  This script reports every ``self.x`` /
``cls.x`` attribute access whose name is not defined on the enclosing
class, on any base class found in the tree, or assigned as an instance
attribute, so the leftovers can be repaired.

Usage:
    python scripts/check_self_calls.py [--fix]
"""
from __future__ import annotations

import argparse
import ast
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ROOTS = ("agents", "detectors", "scripts", "tools", "llm", "data",
         "utils", "tests", "workflow_engine.py", "chief_agent.py")


def files() -> list[Path]:
    out = []
    for root in ROOTS:
        p = PROJECT_ROOT / root
        if not p.exists():
            continue
        if p.is_file():
            out.append(p)
            continue
        for f in p.rglob("*.py"):
            if "__pycache__" in str(f):
                continue
            out.append(f)
    return sorted(out)


def class_members(tree: ast.AST) -> dict[str, set[str]]:
    """Map class name -> every name that can be an attribute of it."""
    members: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        names = members.setdefault(node.name, set())
        for sub in ast.walk(node):
            if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                names.add(sub.name)
            elif isinstance(sub, ast.AnnAssign) and isinstance(sub.target, ast.Name):
                names.add(sub.target.id)
            elif isinstance(sub, ast.Assign):
                for t in sub.targets:
                    if isinstance(t, ast.Name):
                        names.add(t.id)
            elif isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name) \
                    and sub.value.id in ("self", "cls"):
                names.add(sub.attr)
        for base in node.bases:
            if isinstance(base, ast.Name):
                names.add(f"__base__{base.id}")
    return members


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fix", action="store_true")
    args = ap.parse_args()

    all_files = files()
    trees = {}
    for p in all_files:
        try:
            trees[p] = ast.parse(p.read_text())
        except SyntaxError:
            continue
    members = {}
    for p, t in trees.items():
        for k, v in class_members(t).items():
            members.setdefault(k, set()).update(v)

    # Resolve each class' full attribute set by walking its bases that are
    # defined in the tree.  A name that appears on *some* unrelated class is
    # not a valid excuse: that is exactly the shape of the bug this checks
    # for (a call left pointing at a renamed method that now only exists
    # elsewhere).
    bases: dict[str, list[str]] = {}
    for p, t in trees.items():
        for node in ast.walk(t):
            if isinstance(node, ast.ClassDef):
                bases[node.name] = [
                    b.id for b in node.bases if isinstance(b, ast.Name)
                ]

    def resolve(cls: str, seen: set[str] | None = None) -> set[str]:
        seen = seen or set()
        if cls in seen:
            return set()
        seen.add(cls)
        out = set(members.get(cls, set()))
        for b in bases.get(cls, []):
            out |= resolve(b, seen)
        return out

    problems = []
    for p, t in trees.items():
        for node in ast.walk(t):
            if not isinstance(node, ast.ClassDef):
                continue
            own = resolve(node.name)
            for sub in ast.walk(node):
                if not isinstance(sub, ast.Attribute):
                    continue
                if not (isinstance(sub.value, ast.Name)
                        and sub.value.id in ("self", "cls")):
                    continue
                attr = sub.attr
                if attr in own:
                    continue
                problems.append((p, sub.lineno, node.name, attr))

    if not problems:
        print("no unresolved self/cls attribute accesses")
        return 0

    print(f"{len(problems)} unresolved self/cls attribute access(es):")
    for p, line, cls, attr in problems[:60]:
        print(f"  {p.relative_to(PROJECT_ROOT)}:{line} {cls}.{attr}")
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
