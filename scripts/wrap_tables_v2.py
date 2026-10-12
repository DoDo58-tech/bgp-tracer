#!/usr/bin/env python3
"""Surgical table-width fix.

Strategy: only add a width-control directive to tables whose column
specifications sum to more than 0.95\linewidth. For those, we:

  - Replace `\centering` with `\centering` + (if missing) a
    `\footnotesize` to slightly shrink text.
  - Wrap the inner tabular in `\resizebox{\linewidth}{!}{...}` with
    a SAFE form: we DON'T use `\small` (which can be a problem when
    the original is already `\small`). We use `\setlength{\tabcolsep}{3pt}`
    to reduce inter-column padding.

For tables that are <= 0.95\linewidth, we do nothing (they already fit).

This script also fixes the "trailing `%`" issue: the close of the
resizebox must be on its own line and not have stray spaces.

Idempotent: running it twice is a no-op.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "docs" / "paper"


def parse_col_spec(spec: str) -> float:
    """Sum of the linewidths in a tabular column spec."""
    total = 0.0
    for m in re.finditer(r'p\{([\d.]+)\\linewidth\}', spec):
        total += float(m.group(1))
    # l, c, r, plus column separators add 6pt = ~0.08\linewidth
    n_other = len(re.findall(r'(?<![lcr])[lcr](?![lcr])', spec))
    return total + n_other * 0.04  # rough estimate


def find_table_blocks(text: str):
    """Yield (start, end, tabular_start, tabular_end, col_spec) for
    every \begin{table}...\end{table} block with a tabular inside."""
    pos = 0
    while True:
        bt = text.find(r'\begin{table}', pos)
        if bt == -1:
            return
        et = text.find(r'\end{table}', bt)
        if et == -1:
            return
        et_end = et + len(r'\end{table}')
        block = text[bt:et_end]
        tab_m = re.search(r'\\begin\{tabular\}(\{[^}]+\})', block)
        if tab_m:
            yield (bt, et_end,
                   bt + tab_m.end(),
                   None,
                   tab_m.group(1))
        pos = et_end


def fix_file(p: Path) -> int:
    text = p.read_text()
    blocks = list(find_table_blocks(text))
    if not blocks:
        return 0
    # process from last to first so indices stay valid
    n_changed = 0
    for bt, et_end, _tab_start, _junk, col_spec in reversed(blocks):
        ratio = parse_col_spec(col_spec)
        if ratio <= 0.95:
            continue
        # The table is "wide". Insert a \setlength{\tabcolsep}{3pt}
        # directive right after \begin{table}...\centering and ensure
        # the tabular is wrapped. We do NOT touch existing resizebox.
        block = text[bt:et_end]
        if r'\resizebox' in block:
            continue
        new_block = re.sub(
            r'(\\begin\{table\}.*?\\centering\s*\n)',
            r'\1' + r'\setlength{\tabcolsep}{3pt}' + '\n',
            block, count=1, flags=re.DOTALL
        )
        # Wrap the tabular
        new_block = re.sub(
            r'(\\begin\{tabular\}' + re.escape(col_spec) + r'\n)',
            r'\\resizebox{\\linewidth}{!}{%\n' + r'\1',
            new_block, count=1
        )
        # Close the resizebox
        new_block = re.sub(
            r'\\end\{tabular\}\n',
            r'\\end{tabular}\n%}\n',
            new_block, count=1
        )
        text = text[:bt] + new_block + text[et_end:]
        n_changed += 1
    if n_changed:
        p.write_text(text)
    return n_changed


def main():
    for fname in ['section1_intro.tex', 'section2_related.tex',
                  'section3_data.tex', 'section4_method.tex',
                  'section5_css.tex', 'section6.tex',
                  'section7_discussion.tex', 'supplementary.tex']:
        p = ROOT / fname
        if not p.exists():
            continue
        n = fix_file(p)
        print(f"  {fname}: {'updated ' + str(n) + ' tables' if n else 'no change'}")


if __name__ == '__main__':
    main()
