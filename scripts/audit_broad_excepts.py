#!/usr/bin/env python3
"""Find ``except Exception`` blocks that guard nothing risky.

An ``except Exception`` around pure local computation -- a dict lookup,
a format call, a numeric conversion on a value already validated --
costs a reader the reason for the guard while protecting against
nothing.  Around I/O, around a call into a third-party library, or
around a call that is *known* to raise, the guard earns its place.

This script classifies every ``except Exception`` handler by whether the
guarded body can actually raise something outside the caller's control,
and reports the ones that cannot.

Usage:
    python scripts/audit_broad_excepts.py [--verbose]
"""
from __future__ import annotations

import argparse
import ast
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ROOTS = ("agents", "detectors", "scripts", "tools", "llm", "data", "utils",
         "workflow_engine.py", "chief_agent.py")

# Calls that can raise for reasons outside the caller's control: network,
# filesystem, subprocess, third-party libraries, and the project's own
# detector / LLM layers.
RISKY_ROOTS = (
    "requests", "httpx", "urllib", "socket", "aiohttp",
    "open", "Path", "os", "shutil", "subprocess", "polars", "pandas",
    "numpy", "scipy", "pywt", "yaml", "json", "gzip", "bz2", "lzma",
    "pd", "np", "pl", "client", "session", "get", "post", "put",
    "read_text", "write_text", "read_bytes", "write_bytes", "mkdir",
    "glob", "rglob", "iterdir", "unlink", "rename", "copy", "move",
    "exists", "stat",
    "analyze", "detect", "fetch", "run", "call", "invoke", "execute",
    "query", "search", "lookup", "resolve", "download", "upload",
    "load", "save", "parse", "build", "compute", "generate", "complete",
    "chat", "acreate", "ainvoke", "invoke", "stream", "sleep",
    "sqlalchemy", "redis", "psycopg", "boto",
)

# Exceptions that are *expected* from the guarded call and therefore
# justify a narrow guard.
EXPECTED = ("ValueError", "TypeError", "KeyError", "IndexError",
            "AttributeError", "ZeroDivisionError", "OverflowError",
            "StopIteration", "ArithmeticError", "UnicodeDecodeError")


def is_risky(node: ast.AST) -> bool:
    """True when the expression can raise for external reasons."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            func = sub.func
            if isinstance(func, ast.Name):
                name = func.id.lower()
            elif isinstance(func, ast.Attribute):
                name = func.attr.lower()
            else:
                name = ""
            if any(name == r or name.startswith(r + "_") or r in name
                   for r in RISKY_ROOTS):
                return True
        if isinstance(sub, ast.Await):
            return True
        if isinstance(sub, (ast.BinOp, ast.Compare)):
            for child in ast.walk(sub):
                if isinstance(child, ast.BinOp) and isinstance(child.op, ast.Div):
                    return True
    return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    files: list[Path] = []
    for root in ROOTS:
        p = PROJECT_ROOT / root
        if not p.exists():
            continue
        files += [p] if p.is_file() else [
            f for f in p.rglob("*.py") if "__pycache__" not in str(f)
        ]

    removable: list[tuple[Path, int, str]] = []
    total = 0
    for p in sorted(files):
        try:
            tree = ast.parse(p.read_text())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Try):
                continue
            for h in node.handlers:
                if not (isinstance(h.type, ast.Name)
                        and h.type.id == "Exception"):
                    continue
                total += 1
                risky = any(is_risky(s) for s in h.body)
                if risky:
                    continue
                # A handler that logs or re-raises is doing work, not
                # silently swallowing; only the bare ones are candidates.
                bare = len(h.body) == 1 and isinstance(
                    h.body[0], ast.Pass)
                if not bare:
                    continue
                removable.append((p, h.lineno, "swallow"))

    print(f"{total} ``except Exception`` handler(s) found")
    print(f"{len(removable)} guard(s) nothing risky and swallow the error:")
    for p, line, kind in removable:
        rel = p.relative_to(PROJECT_ROOT)
        if args.verbose:
            print(f"  {rel}:{line}")
    if not args.verbose:
        by_file: dict[str, int] = {}
        for p, _, _ in removable:
            by_file[str(p.relative_to(PROJECT_ROOT))] = \
                by_file.get(str(p.relative_to(PROJECT_ROOT)), 0) + 1
        for f, n in sorted(by_file.items(), key=lambda kv: -kv[1]):
            print(f"  {n:4d}  {f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
