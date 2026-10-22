#!/usr/bin/env python3
"""Strip ``\\medskip\\noindent\\textbf{...}`` run-in lead-ins.

One regex pass; each match consumes the whole bold group (nested braces
handled by the alternation) plus the whitespace that follows it, and is
re-emitted as ``<head>. `` (bold removed, no paragraph break). Nothing
outside the match is touched, so file length can only shrink.
"""
from __future__ import annotations
import re, sys
from pathlib import Path

PAPER = Path("/data/bgp_tracer/docs/paper")
PAT = re.compile(
    r"\\medskip\\noindent\\textbf\{"
    r"((?:[^{}\\]|\\.|{(?:[^{}\\]|\\.)*\})*?)"
    r"\}[ \t]*\n?[ \t]*"
)

def repl(m: re.Match) -> str:
    head = re.sub(r"\s+", " ", m.group(1)).strip()
    if head and not head.endswith((".", "!", "?", ":", ";")):
        head += "."
    return head + " "

def main() -> int:
    total = 0
    for f in sorted(PAPER.glob("*.tex")):
        s = f.read_text(encoding="utf-8")
        if "\\medskip\\noindent\\textbf" not in s:
            continue
        new, n = PAT.subn(repl, s)
        assert len(new) <= len(s), f"{f.name} grew unexpectedly"
        f.write_text(new, encoding="utf-8")
        print(f"{f.name}: {n}  ({len(s)} -> {len(new)} bytes)")
        total += n
    print(f"\ntotal: {total}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
