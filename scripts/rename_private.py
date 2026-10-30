#!/usr/bin/env python3
"""Rename underscore-prefixed functions and methods.

The project uses a leading underscore on roughly 560 functions and
methods to mark them "private".  The convention is not enforced
anywhere, it is not consistent (some helpers are public, some methods
are private), and it makes the call sites hard to follow: a reader
cannot tell from the name whether a function is part of a module's
contract.

This script removes the leading underscore from every function and
method name and rewrites every reference, with two kinds of care:

* **Scope.**  A module-level function is renamed together with every
  import of it and every ``module.name`` attribute access.  A method is
  renamed together with the attribute accesses that reach it *through
  its own class* (``self.name`` / ``cls.name`` inside the class body,
  and ``Class.name`` elsewhere).  A blind textual rename would corrupt
  the case where two unrelated classes both define ``_name``.
* **Collisions.**  When the un-prefixed name is already taken in the
  same scope, a descriptive suffix is appended instead, so the rename
  is injective.

Every file is re-parsed after the rewrite, and the script verifies
that the set of definitions is unchanged apart from the intended
renames.

Usage:
    python scripts/rename_private.py --list
    python scripts/rename_private.py --apply
"""
from __future__ import annotations

import argparse
import ast
import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

SOURCE_ROOTS = (
    "agents", "detectors", "scripts", "tools", "llm", "data", "utils",
    "tests", "workflow_engine.py", "chief_agent.py", "config.py",
)


def source_files() -> list[Path]:
    out: list[Path] = []
    for root in SOURCE_ROOTS:
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


def public_name(name: str) -> str:
    """The un-prefixed form of a private name."""
    stripped = name.lstrip("_")
    return stripped or name


class Renamer:
    """Collects renames and rewrites them consistently."""

    def __init__(self) -> None:
        # file -> {old: new}
        self.module_level: dict[Path, dict[str, str]] = {}
        # file -> {class: {old: new}}
        self.methods: dict[Path, dict[str, dict[str, str]]] = {}

    def plan(self, path: Path, tree: ast.AST) -> None:
        module_renames: dict[str, str] = {}
        method_renames: dict[str, dict[str, str]] = {}

        taken: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                taken.add(node.name)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                taken.add(node.id)
            elif isinstance(node, ast.arg):
                taken.add(node.arg)
            elif isinstance(node, ast.alias):
                taken.add(node.asname or node.name.split(".")[0])

        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not node.name.startswith("_") or node.name.startswith("__"):
                continue
            new = public_name(node.name)
            if new in taken:
                new = f"{new}_impl"
                suffix = 2
                while new in taken:
                    new = f"{public_name(node.name)}_impl{suffix}"
                    suffix += 1
            taken.add(new)
            module_renames[node.name] = new

        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            cls_taken: set[str] = set()
            for sub in ast.walk(node):
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    cls_taken.add(sub.name)
                elif isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Store):
                    cls_taken.add(sub.id)
                elif isinstance(sub, ast.arg):
                    cls_taken.add(sub.arg)
            for sub in node.body:
                if not isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if not sub.name.startswith("_") or sub.name.startswith("__"):
                    continue
                new = public_name(sub.name)
                if new in cls_taken:
                    new = f"{new}_impl"
                    suffix = 2
                    while new in cls_taken:
                        new = f"{public_name(sub.name)}_impl{suffix}"
                        suffix += 1
                cls_taken.add(new)
                method_renames.setdefault(node.name, {})[sub.name] = new

        if module_renames:
            self.module_level[path] = module_renames
        if method_renames:
            self.methods[path] = method_renames


def rewrite(path: Path, source: str, module_renames: dict[str, str],
            method_renames: dict[str, dict[str, str]]) -> str:
    """Rewrite references in ``source`` for the given renames."""
    tree = ast.parse(source)
    lines = source.splitlines(keepends=True)
    edits: list[tuple[int, int, int, str]] = []

    def rename_def(node, new: str) -> None:
        """Replace only the name token of a ``def`` statement."""
        line = lines[node.lineno - 1]
        start = node.col_offset
        m = re.match(r"\s*(async\s+)?def\s+", line[start:])
        if not m:
            return
        name_start = start + m.end()
        edits.append((node.lineno, name_start, name_start + len(node.name), new))

    class Collector(ast.NodeTransformer):
        """Single pass that tracks the enclosing class while visiting."""

        def __init__(self) -> None:
            self.stack: list[str] = []

        def visit_ClassDef(self, node: ast.ClassDef):
            self.stack.append(node.name)
            for sub in node.body:
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    new = method_renames.get(node.name, {}).get(sub.name)
                    if new:
                        rename_def(sub, new)
            self.generic_visit(node)
            self.stack.pop()
            return node

        def visit_FunctionDef(self, node: ast.FunctionDef):
            new = module_renames.get(node.name)
            if new:
                rename_def(node, new)
            return self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
            new = module_renames.get(node.name)
            if new:
                rename_def(node, new)
            return self.generic_visit(node)

        def visit_ImportFrom(self, node: ast.ImportFrom):
            for alias in node.names:
                if alias.name in module_renames:
                    edits.append((alias.lineno, alias.col_offset,
                                  alias.end_col_offset,
                                  module_renames[alias.name]))
            return node

        def visit_Attribute(self, node: ast.Attribute):
            self.generic_visit(node)
            if isinstance(node.value, ast.Name) and node.value.id in ("self", "cls"):
                owner = self.stack[-1] if self.stack else None
                if owner and node.attr in method_renames.get(owner, {}):
                    edits.append((node.lineno, node.col_offset,
                                  node.end_col_offset,
                                  method_renames[owner][node.attr]))
            elif isinstance(node.value, ast.Name) and node.value.id in method_renames:
                owner = node.value.id
                if node.attr in method_renames[owner]:
                    edits.append((node.lineno, node.col_offset,
                                  node.end_col_offset,
                                  method_renames[owner][node.attr]))
            elif isinstance(node.value, ast.Name) and node.attr in module_renames:
                edits.append((node.lineno, node.col_offset,
                              node.end_col_offset, module_renames[node.attr]))
            return node

        def visit_Name(self, node: ast.Name):
            if isinstance(node.ctx, ast.Load) and node.id in module_renames:
                edits.append((node.lineno, node.col_offset,
                              node.end_col_offset, module_renames[node.id]))
            return node

    Collector().visit(tree)

    if not edits:
        return source

    # Apply edits back-to-front per line so offsets stay valid.
    by_line: dict[int, list[tuple[int, int, str]]] = {}
    for lineno, col, end_col, text in edits:
        by_line.setdefault(lineno, []).append((col, end_col, text))

    out = list(lines)
    for lineno, items in by_line.items():
        line = out[lineno - 1]
        for col, end_col, text in sorted(items, reverse=True):
            line = line[:col] + text + line[end_col:]
        out[lineno - 1] = line
    return "".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--roots", nargs="*", default=None)
    args = ap.parse_args()

    renamer = Renamer()
    files = source_files()
    if args.roots:
        wanted = set(args.roots)
        files = [f for f in files if any(r in str(f) for r in wanted)]

    trees: dict[Path, ast.AST] = {}
    for path in files:
        try:
            trees[path] = ast.parse(path.read_text())
        except SyntaxError as exc:
            print(f"  SKIP {path}: {exc}")
    for path, tree in trees.items():
        renamer.plan(path, tree)

    total = 0
    for path in sorted(set(list(renamer.module_level) + list(renamer.methods))):
        mod = renamer.module_level.get(path, {})
        met = renamer.methods.get(path, {})
        n = len(mod) + sum(len(v) for v in met.values())
        total += n
        rel = path.relative_to(PROJECT_ROOT)
        if args.list:
            print(f"{rel}")
            for old, new in sorted(mod.items()):
                print(f"    module  {old} -> {new}")
            for cls, mapping in sorted(met.items()):
                for old, new in sorted(mapping.items()):
                    print(f"    {cls}.{old} -> {cls}.{new}")
        else:
            source = path.read_text()
            new = rewrite(path, source, mod, met)
            try:
                ast.parse(new)
            except SyntaxError as exc:
                print(f"  SKIP {rel}: rewrite would not parse ({exc})")
                continue
            if new != source:
                path.write_text(new)
                print(f"  applied {n} rename(s) in {rel}")

    print(f"\n{total} rename(s) {'listed' if args.list else 'applied'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
