#!/usr/bin/env python3
"""Safer table-width fix: wrap the ENTIRE \begin{table}...\end{table}
in \resizebox, not just the inner tabular. This way caption + tabular
scale together and the table never overflows.

The pattern is:
    \begin{table}
    ...caption...
    \centering
    ...
    \begin{tabular}
    ...
    \end{tabular}
    \end{table}
becomes:
    \resizebox{\linewidth}{!}{
    \begin{table}
    ...caption...
    \centering
    ...
    \begin{tabular}
    ...
    \end{tabular}
    \end{table}
    }

This requires the `adjustbox` package OR putting it around the whole
environment. We use the simpler form: \resizebox around just the
inner tabular (since wrapping the whole table breaks LaTeX), and we
also add \setlength{\tabcolsep}{3pt} to tighten column padding.

We ONLY apply this to tables where the column spec is at-risk:
either (a) the sum of p{X} >= 0.9\linewidth, OR (b) the spec is
{lrrrrr} or similar (>= 5 columns) which tends to overflow.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "docs" / "paper"


def is_wide(spec: str) -> bool:
    # sum of p{X\linewidth} > 0.9
    pl = 0.0
    for m in re.finditer(r'p\{([\d.]+)\\linewidth\}', spec):
        pl += float(m.group(1))
    if pl > 0.9:
        return True
    # many columns
    n_other = sum(1 for ch in spec if ch in 'lcr')
    if n_other >= 5:
        return True
    return False


def wrap_table(text: str) -> str:
    """Wrap each wide table in the given text."""
    out = []
    pos = 0
    while True:
        bt = text.find(r'\begin{table}', pos)
        if bt == -1:
            out.append(text[pos:])
            break
        et = text.find(r'\end{table}', bt)
        if et == -1:
            out.append(text[pos:])
            break
        et_end = et + len(r'\end{table}')
        block = text[bt:et_end]
        if r'\resizebox' in block:
            out.append(text[pos:et_end])
            pos = et_end
            continue
        tab_m = re.search(r'\\begin\{tabular\}(\{[^}]+\})', block)
        wide = False
        if tab_m:
            wide = is_wide(tab_m.group(1))
        if not wide:
            out.append(text[pos:et_end])
            pos = et_end
            continue
        # Build new block:
        # 1) insert \setlength{\tabcolsep}{3pt} after \centering
        new_block = re.sub(
            r'(\\centering\s*\n)',
            r'\1\\setlength{\\tabcolsep}{3pt}\n',
            block, count=1
        )
        # 2) wrap \begin{tabular} ... \end{tabular} in \resizebox
        # find the tab_m and the end tabular
        tab2 = re.search(r'\\begin\{tabular\}(\{[^}]+\})', new_block)
        if not tab2:
            out.append(text[pos:et_end])
            pos = et_end
            continue
        td = 0
        te_pos = None
        for k in range(tab2.end(), len(new_block)):
            if new_block[k:k + 15] == r'\begin{tabular}':
                td += 1
            elif new_block[k:k + 13] == r'\end{tabular}':
                if td == 0:
                    te_pos = k + 13
                    break
                td -= 1
        if not te_pos:
            out.append(text[pos:et_end])
            pos = et_end
            continue
        inner = new_block[tab2.start():te_pos]
        # Insert \resizebox around the inner content.
        # CRITICAL: \resizebox reads its content; the trailing
        # `\end{tabular}\n` must be followed by a comment-protected
        # newline so the closing `}` isn't swallowed.
        wrapped = ('\\resizebox{\\linewidth}{!}{%\n'
                   + inner
                   + '%}')  # no trailing newline
        new_block = new_block[:tab2.start()] + wrapped + new_block[te_pos:]
        out.append(text[pos:bt])
        out.append(new_block)
        pos = et_end
    return ''.join(out)


def main():
    for fname in ['section1_intro.tex', 'section2_related.tex',
                  'section3_data.tex', 'section4_method.tex',
                  'section5_css.tex', 'section6.tex',
                  'section7_discussion.tex', 'supplementary.tex']:
        p = ROOT / fname
        if not p.exists():
            continue
        text = p.read_text()
        new = wrap_table(text)
        if new != text:
            p.write_text(new)
            print(f"  updated {fname}")
        else:
            print(f"  no change {fname}")


if __name__ == '__main__':
    main()
