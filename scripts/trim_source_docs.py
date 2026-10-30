"""Trim oversized docstrings and inline comment blocks."""
#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

# Docstring paragraphs that describe a history rather than a contract.
HISTORY_MARKERS = (
    "bug fix", "bugfix", "bug (", "bug(", "rounded-", "round-",
    "fixed in", "was changed", "previously", "used to ", "historically",
    "as of 20", "deprecated", "note (202", "(2026-", "(2025-",
    "issue #", "bug-#", "workaround", "temporary fix",
)

# Paragraph starters that signal a *contract* worth keeping.
CONTRACT_MARKERS = (
    "returns", "return ", "raises", "arguments", "parameters", "yields",
    "guarantee", "must ", "requires", "warning:",
    "the caller", "callers", "side effect", "thread-safe",
    "do not ", "does not ", "kept", "if ", "when ",
    "the key", "the value", "the name", "the format", "the schema",
    "the shape", "the order", "the size", "the type", "the only",
    "by default", "override", "env var", "environment variable",
    "deterministic", "example", "e.g.",
)

MAX_DOCSTRING_LINES = 4
MAX_INLINE_COMMENT_LINES = 3


def is_history(paragraph: str) -> bool:
    low = paragraph.lower()
    return any(m in low for m in HISTORY_MARKERS)


def is_contract(paragraph: str) -> bool:
    low = paragraph.lower().lstrip()
    return any(low.startswith(m) for m in CONTRACT_MARKERS)


def trim_docstring(body: str) -> str:
    """Reduce a docstring body to its summary plus contract paragraphs."""
    lines = body.expandtabs().splitlines()
    if len(lines) <= MAX_DOCSTRING_LINES:
        return body
    paragraphs: list[list[str]] = []
    cur: list[str] = []
    for ln in lines:
        if not ln.strip():
            if cur:
                paragraphs.append(cur)
                cur = []
            continue
        cur.append(ln.strip())
    if cur:
        paragraphs.append(cur)
    if not paragraphs:
        return body
    keep = [paragraphs[0]]
    for para in paragraphs[1:]:
        text = " ".join(para)
        if is_history(text):
            continue
        if is_contract(text):
            keep.append(para)
        if sum(len(p) for p in keep) >= MAX_DOCSTRING_LINES:
            break
    out: list[str] = []
    for i, para in enumerate(keep):
        if i:
            out.append("")
        out.extend(para)
    return "\n".join(out)


def docstring_spans(tree: ast.AST) -> list[tuple[int, int, str]]:
    """Return ``(lineno, end_lineno, body)`` for every docstring."""
    spans: list[tuple[int, int, str]] = []
    holders = (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
    for node in ast.walk(tree):
        if not isinstance(node, holders):
            continue
        body = getattr(node, "body", None)
        if not body:
            continue
        first = body[0]
        if not (isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)):
            continue
        if first.end_lineno is None:
            continue
        spans.append((first.lineno, first.end_lineno, first.value.value))
    return spans


def apply_docstring_trims(source: str, tree: ast.AST) -> str:
    lines = source.splitlines()
    spans = docstring_spans(tree)
    # Replace from the bottom up so earlier line numbers stay valid.
    for start, end, body in sorted(spans, reverse=True):
        trimmed = trim_docstring(body)
        if trimmed == body:
            continue
        quote = '"""' if body.lstrip().startswith('"""') or '"""' in lines[start - 1] else "'''"
        indent = re.match(r"\s*", lines[start - 1]).group(0)
        new_text = quote + trimmed + quote
        new_lines = [indent + ln if idx else indent + ln
                     for idx, ln in enumerate(new_text.split("\n"))]
        lines[start - 1:end] = new_lines
    return "\n".join(lines)


def trim_comments(source: str) -> str:
    """Collapse long inline comment blocks to their first line."""
    lines = source.splitlines()
    out: list[str] = []
    block: list[str] = []

    def flush() -> None:
        if not block:
            return
        if len(block) > MAX_INLINE_COMMENT_LINES:
            out.append(block[0].rstrip())
        else:
            out.extend(b.rstrip() for b in block)
        block.clear()

    in_doc = False
    for raw in lines:
        stripped = raw.strip()
        if not in_doc and (stripped.startswith('"""') or stripped.startswith("'''")):
            if len(stripped) > 3 and stripped.endswith(stripped[:3]):
                out.append(raw)
                continue
            in_doc = True
            out.append(raw)
            continue
        if in_doc:
            out.append(raw)
            if stripped.endswith('"""') or stripped.endswith("'''"):
                in_doc = False
            continue
        if stripped.startswith("#"):
            indent = raw[: len(raw) - len(raw.lstrip())]
            block.append(indent + stripped)
            continue
        flush()
        out.append(raw)
    flush()
    return "\n".join(out)


def process(path: Path, apply: bool) -> tuple[bool, str]:
    original = path.read_text()
    try:
        tree = ast.parse(original)
    except SyntaxError as exc:
        return False, f"parse error: {exc}"
    before = sorted(
        n.name for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    )
    new = trim_comments(apply_docstring_trims(original, tree))
    if new == original:
        return False, "no change"
    try:
        new_tree = ast.parse(new)
    except SyntaxError as exc:
        return False, f"would not parse: {exc}"
    after = sorted(
        n.name for n in ast.walk(new_tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    )
    if before != after:
        return False, "definition set changed"
    if apply:
        path.write_text(new)
    return True, "trimmed"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="*", default=None)
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()

    roots = [Path(p) for p in args.paths] if args.paths else [
        PROJECT_ROOT / "agents", PROJECT_ROOT / "detectors",
        PROJECT_ROOT / "scripts", PROJECT_ROOT / "tools",
        PROJECT_ROOT / "llm", PROJECT_ROOT / "data",
        PROJECT_ROOT / "utils", PROJECT_ROOT / "workflow_engine.py",
        PROJECT_ROOT / "chief_agent.py",
    ]
    files: list[Path] = []
    for root in roots:
        if root.is_file():
            files.append(root)
            continue
        if not root.exists():
            continue
        for p in root.rglob("*.py"):
            if any(s in str(p) for s in ("__pycache__", ".venv")):
                continue
            files.append(p)

    changed = 0
    for p in sorted(set(files)):
        ok, msg = process(p, args.apply)
        rel = p.relative_to(PROJECT_ROOT) if p.is_absolute() else p
        if ok:
            changed += 1
            print(f"  {'applied' if args.apply else 'would trim'}: {rel}")
        elif msg != "no change":
            print(f"  SKIP ({msg}): {rel}")
    print(f"\n{changed} file(s) {'trimmed' if args.apply else 'would be trimmed'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())