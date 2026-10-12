#!/usr/bin/env python3
"""Wrap ALL \begin{tabular}...\end{tabular} blocks (that live inside a
table environment) in \resizebox{\linewidth}{!}{...}.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "docs" / "paper"


def wrap_all(text: str) -> str:
    out = []
    i = 0
    while i < len(text):
        # find the next \begin{tabular} that hasn't been wrapped yet
        tab_m = re.search(r'\\begin\{tabular\}', text[i:])
        if not tab_m:
            out.append(text[i:])
            break
        abs_start = i + tab_m.start()
        # already wrapped? (preceded by \resizebox)
        # check 20 chars before
        prefix = text[max(0, abs_start - 40):abs_start]
        if r'\resizebox' in prefix:
            # skip this one, advance past it
            out.append(text[i:abs_start + len(r'\begin{tabular}')])
            i = abs_start + len(r'\begin{tabular}')
            continue
        # find matching \end{tabular}
        td = 0
        te = None
        for k in range(abs_start + len(r'\begin{tabular}'), len(text)):
            if text[k:k + 15] == r'\begin{tabular}':
                td += 1
            elif text[k:k + 13] == r'\end{tabular}':
                if td == 0:
                    te = k + 13
                    break
                td -= 1
        if not te:
            out.append(text[i:])
            break
        # find enclosing \begin{table} ... \end{table}
        # back-scan to find \begin{table}
        bt = text.rfind(r'\begin{table}', 0, abs_start)
        if bt == -1:
            # tabular is not inside a table; skip
            out.append(text[i:te])
            i = te
            continue
        # find \end{table} after the \end{tabular}
        et = text.find(r'\end{table}', te)
        if et == -1:
            out.append(text[i:te])
            i = te
            continue
        # emit text before the tabular
        out.append(text[i:abs_start])
        # wrap the inner tabular
        inner = text[abs_start:te]
        out.append(r'\resizebox{\linewidth}{!}{%' + '\n')
        out.append(inner)
        out.append('\n%}\n')
        i = te
    return ''.join(out)


def main():
    for fname in ['section3_data.tex', 'section6.tex', 'section4_method.tex',
                  'section5_css.tex', 'section1_intro.tex',
                  'section2_related.tex', 'section7_discussion.tex',
                  'supplementary.tex']:
        p = ROOT / fname
        if not p.exists():
            continue
        text = p.read_text()
        new = wrap_all(text)
        if new != text:
            p.write_text(new)
            print(f"  updated {fname}")
        else:
            print(f"  no change {fname}")


if __name__ == '__main__':
    main()
