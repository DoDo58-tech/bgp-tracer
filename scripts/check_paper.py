#!/usr/bin/env python3
"""Static check for the BGP Tracer paper LaTeX source.

Catches the kinds of issues that would cause pdflatex to fail:
  - \input{...} files that do not exist
  - \includegraphics{...} files that do not exist
  - \cite{...} keys that are not in refs.bib
  - \ref{...} labels that are never \label{...}'d

Usage:
  python scripts/check_paper.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "docs" / "paper"
PAPER_DIR = ROOT


def find_files_with_ext(root: Path, ext: str) -> list[Path]:
    return sorted(root.rglob(f"*{ext}"))


def collect_input(tex: str) -> set[str]:
    return set(re.findall(r"\\input\{([^}]+)\}", tex))


def collect_includegraphics(tex: str) -> set[str]:
    return set(re.findall(r"\\includegraphics(?:\[[^\]]*\])?\{([^}]+)\}", tex))


def collect_cite(tex: str) -> set[str]:
    # Matches \cite{...}, \citet{...}, \citep{...}, \citealp{...}, \citeyear{...}
    keys = set()
    for m in re.finditer(r"\\cite[a-z]*\*?(?:\[[^\]]*\])?\{([^}]+)\}", tex):
        keys.update(k.strip() for k in m.group(1).split(","))
    return keys


def collect_ref(tex: str) -> set[str]:
    keys = set()
    for m in re.finditer(r"\\(?:ref|vref|autoref|cref|Cref|eqref|nameref)\*?\{([^}]+)\}", tex):
        keys.update(k.strip() for k in m.group(1).split(","))
    return keys


def collect_label(tex: str) -> set[str]:
    return set(re.findall(r"\\label\{([^}]+)\}", tex))


def main() -> int:
    if not PAPER_DIR.exists():
        print(f"FATAL: paper dir not found at {PAPER_DIR}", file=sys.stderr)
        return 1

    tex_files = [PAPER_DIR / "main.tex"] + sorted(PAPER_DIR.glob("section*.tex"))
    if not tex_files:
        print(f"FATAL: no .tex files in {PAPER_DIR}", file=sys.stderr)
        return 1

    all_text = ""
    for tf in tex_files:
        all_text += tf.read_text() + "\n"

    issues: list[str] = []

    # 1. \input{...} files
    for f in collect_input(all_text):
        p = PAPER_DIR / f"{f}.tex"
        if not p.exists():
            issues.append(f"  \\input{{{f}}} → {p.relative_to(PAPER_DIR.parent)} does not exist")

    # 2. \includegraphics{...} files
    for f in collect_includegraphics(all_text):
        p = PAPER_DIR / f
        if not p.exists():
            issues.append(f"  \\includegraphics{{{f}}} → does not exist")

    # 3. \cite{...} keys
    bib = PAPER_DIR / "refs.bib"
    bib_text = bib.read_text() if bib.exists() else ""
    bib_keys = set(re.findall(r"@\w+\{([^,]+),", bib_text))
    for k in collect_cite(all_text):
        if k not in bib_keys:
            issues.append(f"  \\cite{{{k}}} → not in refs.bib")

    # 4. \ref{...} labels
    labels = collect_label(all_text)
    for k in collect_ref(all_text):
        if k not in labels:
            issues.append(f"  \\ref{{{k}}} → no matching \\label{{{k}}}")

    # 5. Top-level structural sanity
    main = (PAPER_DIR / "main.tex").read_text()
    if r"\begin{document}" not in main:
        issues.append("  main.tex has no \\begin{document}")
    if r"\end{document}" not in main:
        issues.append("  main.tex has no \\end{document}")
    if r"\maketitle" not in main:
        issues.append("  main.tex has no \\maketitle")
    if r"\bibliography{" not in main:
        issues.append("  main.tex has no \\bibliography{...}")

    if issues:
        print(f"PAPER CHECK FAILED ({len(issues)} issues):\n")
        print("\n".join(issues))
        return 1

    print("PAPER CHECK PASSED:")
    print(f"  {len(tex_files)} .tex files scanned")
    print(f"  {len(collect_input(all_text))} \\input references")
    print(f"  {len(collect_includegraphics(all_text))} \\includegraphics references")
    print(f"  {len(collect_cite(all_text))} \\cite keys (all in refs.bib)")
    print(f"  {len(labels)} \\label definitions, {len(collect_ref(all_text))} \\ref references (all resolved)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
