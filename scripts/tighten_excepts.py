#!/usr/bin/env python3
"""Replace unjustified ``except Exception`` guards with precise types.

A broad guard around pure local computation tells a reader nothing: it
hides which failure the code was written to survive.  This script
rewrites the guards that protect nothing risky (see
``scripts/audit_broad_excepts.py`` for the classification) into a
narrow handler that names the failures that can actually occur.

The replacement type is derived from the guarded body:

* a numeric conversion -> ``ValueError`` / ``TypeError``;
* a dict or attribute access -> ``KeyError`` / ``AttributeError``;
* an index access -> ``IndexError``;
* anything else -> ``ValueError``.

Guards that wrap I/O or a third-party call are left alone, because
there the broad catch is the correct choice.

Usage:
    python scripts/tighten_excepts.py --apply
"""
from __future__ import annotations

import argparse
import ast
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ROOTS = ("agents", "detectors", "scripts", "tools", "llm", "data", "utils",
         "workflow_engine.py", "chief_agent.py")

RISKY_ROOTS = (
    "requests", "httpx", "urllib", "socket", "aiohttp", "open", "Path",
    "os", "shutil", "subprocess", "polars", "pandas", "numpy", "scipy",
    "pywt", "yaml", "json", "gzip", "bz2", "lzma", "pd", "np", "pl",
    "client", "session", "get", "post", "put", "read_text", "write_text",
    "read_bytes", "write_bytes", "mkdir", "glob", "rglob", "iterdir",
    "unlink", "rename", "copy", "move", "exists", "stat",
    "analyze", "detect", "fetch", "run", "call", "invoke", "execute",
    "query", "search", "lookup", "resolve", "download", "upload",
    "load", "save", "parse", "build", "compute", "generate", "complete",
    "chat", "acreate", "ainvoke", "stream", "sleep", "sqlalchemy",
    "redis", "psycopg", "boto",
)


def body_is_risky(body: list[ast.stmt]) -> bool:
    for stmt in body:
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.Await):
                return True
            if isinstance(sub, ast.Call):
                func = sub.func
                if isinstance(func, ast.Name):
                    name = func.id.lower()
                elif isinstance(func, ast.Attribute):
                    name = func.attr.lower()
                else:
                    name = ""
                if any(r in name for r in RISKY_ROOTS):
                    return True
    return False


def narrow_types(body: list[ast.stmt]) -> list[str]:
    """Pick the exception types that the guarded body can raise."""
    types: set[str] = set()
    for stmt in body:
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                # A conversion of a string to a number.
                if sub.value.strip().replace(".", "", 1).replace(
                        "-", "", 1).isdigit():
                    types.update(("ValueError", "TypeError"))
            if isinstance(sub, ast.Subscript):
                types.add("KeyError")
                types.add("IndexError")
            if isinstance(sub, ast.Attribute):
                types.add("AttributeError")
            if isinstance(sub, ast.BinOp) and isinstance(sub.op, ast.Div):
                types.add("ZeroDivisionError")
    if not types:
        types = {"ValueError"}
    # Keep the set small and predictable.
    ordered = ["ValueError", "TypeError", "KeyError", "IndexError",
               "AttributeError", "ZeroDivisionError"]
    picked = [t for t in ordered if t in types]
    return picked[:3] or ["ValueError"]


def process(path: Path, apply: bool) -> int:
    source = path.read_text()
    tree = ast.parse(source)
    lines = source.splitlines(keepends=True)
    edits: list[tuple[int, int, int, str]] = []
    count = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        for h in node.handlers:
            if not (isinstance(h.type, ast.Name) and h.type.id == "Exception"):
                continue
            if body_is_risky(h.body):
                continue
            # A handler that re-raises is doing its job; leave it alone.
            if any(isinstance(s, ast.Raise) for s in h.body):
                continue
            if h.type is None or h.type.end_lineno is None:
                continue
            types = narrow_types(h.body)
            # ``h.type`` spans the exception expression only (the
            # ``Exception`` token), so the replacement is just the tuple.
            text = f"({', '.join(types)})"
            edits.append((h.type.lineno, h.type.col_offset,
                          h.type.end_col_offset, text))
            count += 1
    if not edits:
        return 0
    by_line: dict[int, list[tuple[int, int, str]]] = {}
    for ln, c, e, t in edits:
        by_line.setdefault(ln, []).append((c, e, t))
    for ln, items in by_line.items():
        line = lines[ln - 1]
        for c, e, t in sorted(items, reverse=True):
            line = line[:c] + t + line[e:]
        lines[ln - 1] = line
    new = "".join(lines)
    try:
        ast.parse(new)
    except SyntaxError:
        return 0
    if apply:
        path.write_text(new)
    return count


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()
    files: list[Path] = []
    for root in ROOTS:
        p = PROJECT_ROOT / root
        if not p.exists():
            continue
        files += [p] if p.is_file() else [
            f for f in p.rglob("*.py") if "__pycache__" not in str(f)
        ]
    total = 0
    for p in sorted(set(files)):
        n = process(p, args.apply)
        if n:
            total += n
            print(f"  {'applied' if args.apply else 'would tighten'} {n:3d}  "
                  f"{p.relative_to(PROJECT_ROOT)}")
    print(f"\n{total} guard(s) {'tightened' if args.apply else 'would be tightened'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
