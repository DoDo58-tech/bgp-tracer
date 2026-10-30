#!/usr/bin/env python3
"""Find ``self._name`` / ``self.__name`` references whose target no longer exists.

When leading-underscore function names were stripped, a method
``_evidence_quality`` became ``evidence_quality_impl`` (a ``def``-name
rename), but a *call site* ``self._evidence_quality(...)`` was not always
rewritten.  Those call sites parse and import cleanly and only fail the
first time the branch executes.

For every class, this script:
  * collects the attribute names actually defined (methods + class-level
    assignments) and the instance attributes assigned on ``self``,
  * collects every ``self.X`` read,
  * reports reads of an underscore-prefixed X whose stripped form exists
    (``X`` or ``X_impl``) — a rename miss — or whose name exists nowhere.

Usage:
    python scripts/check_self_attributes.py
"""
from __future__ import annotations

import ast
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ROOTS = ("agents", "detectors", "scripts", "tools", "llm", "data", "utils",
         "workflow_engine.py", "chief_agent.py")


def collect(paths: list[Path]):
    # attr-name -> set of classes that define it
    defined: set[str] = set()
    reads: list[tuple[Path, int, str]] = []
    for p in paths:
        try:
            tree = ast.parse(p.read_text())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                defined.add(node.name)
            elif isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) \
                            and t.value.id == "self":
                        defined.add(t.attr)
            elif isinstance(node, ast.AnnAssign):
                t = node.target
                if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) \
                        and t.value.id == "self":
                    defined.add(t.attr)
            elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) \
                    and node.value.id == "self":
                # only record reads (not the target of an assignment)
                reads.append((p, node.lineno, node.attr))

    # assignment targets are also "reads" from ast.walk's perspective; drop
    # the obvious ones by keeping only names that are never assigned.
    assigned: set[str] = set()
    for p in paths:
        try:
            tree = ast.parse(p.read_text())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for t in targets:
                    if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) \
                            and t.value.id == "self":
                        assigned.add(t.attr)

    return defined, assigned, reads


def main() -> int:
    files: list[Path] = []
    for root in ROOTS:
        p = PROJECT_ROOT / root
        if not p.exists():
            continue
        files += [p] if p.is_file() else [
            f for f in p.rglob("*.py") if "__pycache__" not in str(f)
        ]
    files = sorted(set(files))

    defined, assigned, reads = collect(files)

    # A backing field set via ``object.__setattr__(self, '_name', ...)`` is a
    # deliberate recursion-avoidance pattern for a property of the same name
    # (see ``llm/llm_factory.py``); it is not a rename leftover.
    backing: set[str] = set()
    for p in files:
        try:
            tree = ast.parse(p.read_text())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and node.func.attr == "__setattr__" and len(node.args) >= 2:
                a0, a1 = node.args[0], node.args[1]
                if isinstance(a0, ast.Name) and a0.id == "self" \
                        and isinstance(a1, ast.Constant) and isinstance(a1.value, str):
                    backing.add(a1.value)

    known = defined | assigned | backing

    problems: list[tuple[Path, int, str, str]] = []
    for p, line, attr in reads:
        if attr in known:
            continue
        if not attr.startswith("_"):
            continue
        stripped = attr.lstrip("_")
        if stripped in known:
            problems.append((p, line, attr, f"-> {stripped}"))
        elif f"{stripped}_impl" in known:
            problems.append((p, line, attr, f"-> {stripped}_impl"))

    if not problems:
        print("no stale underscore-prefixed self-attribute reads")
        return 0
    print(f"{len(problems)} stale underscore self-attribute read(s):")
    for p, line, attr, where in problems:
        print(f"  {p.relative_to(PROJECT_ROOT)}:{line}  self.{attr}  {where}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
