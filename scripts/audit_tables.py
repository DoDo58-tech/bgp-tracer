#!/usr/bin/env python3
"""Final-pass table layout fixer for IEEEtran two-column paper.

Rule:
- For tables with >2 columns and any cell > 1 line of text -> use table*
  (double-column width) and use \\textwidth-based column widths.
- For tables with 2-3 simple columns -> use table (single-column) and
  use \\columnwidth-based column widths.
- NEVER use \\resizebox (it breaks LaTeX layout).
- NEVER use tabularx with p{} columns (it exceeds column width).
- Always set \\tabcolsep explicitly to keep tables tight.

This script only audits and reports; it does not modify .tex files
(because layout decisions need human review). Run after edits to
verify the layout invariants.
"""
import re
import sys
from pathlib import Path

ROOT = Path("/data/bgp_tracer/docs/paper")

WIDE_TABLES = {
    # table label -> required environment
    "tab:metrics": "table*",
    "tab:misses": "table*",
    "tab:per-cause": "table",
    "tab:method-comparison": "table",
    "tab:loo": "table",
    "tab:heldout": "table",
    "tab:supp-deg-stress": "table",
    "tab:supp-css-n3": "table",
    "tab:supp-uniform-prior": "table",
    "tab:s17-comp": "table",
    "tab:s17-rej": "table",
    "tab:supp-html": "table",
}


def audit_tex_file(path: Path) -> list:
    issues = []
    text = path.read_text()

    # find each \begin{table} or \begin{table*}
    for m in re.finditer(r"\\begin\{table(\*?)\}", text):
        env = "table" + m.group(1)
        block_start = m.end()
        # find matching \end{table*}
        end_match = re.search(r"\\end\{table\*?\}", text[block_start:])
        if not end_match:
            continue
        block = text[block_start : block_start + end_match.start()]
        label_match = re.search(r"\\label\{(tab:[^}]+)\}", block)
        if not label_match:
            continue
        label = label_match.group(1)
        expected = WIDE_TABLES.get(label, "table")
        if env != expected:
            issues.append(
                f"{path.name}: {label} uses {env} but should use {expected}"
            )

        # check for forbidden constructs
        if "\\resizebox" in block:
            issues.append(f"{path.name}: {label} still uses \\resizebox")
        if "\\tabularx" in block and "p{" in block:
            issues.append(
                f"{path.name}: {label} uses tabularx with p{{}} (overflow risk)"
            )

        # check column width semantics
        for cm in re.finditer(r"p\{([^}]+)\}", block):
            unit = cm.group(1)
            if "\\linewidth" in unit and "table*" not in env:
                issues.append(
                    f"{path.name}: {label} uses \\linewidth inside single-column table"
                )
            if "\\textwidth" in unit and env == "table":
                issues.append(
                    f"{path.name}: {label} uses \\textwidth inside single-column table"
                )
            if "\\columnwidth" in unit and "table*" in env:
                # not strictly wrong but unconventional
                pass

    return issues


def main():
    all_issues = []
    for tex in sorted(ROOT.glob("*.tex")):
        if tex.name in ("main.tex",):
            continue
        all_issues.extend(audit_tex_file(tex))

    if not all_issues:
        print("All tables pass layout invariants.")
        return 0
    for issue in all_issues:
        print(f"  - {issue}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
