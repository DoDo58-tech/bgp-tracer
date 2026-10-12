#!/usr/bin/env python3
"""Final, minimal table-width fix — no \\resizebox.

The approach: for each table whose column spec uses p{...\\linewidth},
shrink each p{X\\linewidth} by a factor (default 0.88) so the total
width is < 0.90\\linewidth.  Also add \\setlength{\\tabcolsep}{3pt}
to reduce inter-column padding (8pt → 3pt saves ~5pt per column).

We do NOT touch tables that already use only l/c/r (those auto-shrink).
"""
import re
from pathlib import Path

ROOT = Path("/data/bgp_tracer/docs/paper")
SHRINK = 0.85  # multiply p{X\linewidth} by this factor
TABCOLSEP_PT = 3  # default is 6pt


def shrink_p(match: re.Match) -> str:
    val = float(match.group(1))
    new_val = round(val * SHRINK, 3)
    return f"p{{{new_val:g}\\linewidth}}"


def fix_table_block(block: str) -> str:
    """Shrink p{X\\linewidth} values inside the block."""
    new = re.sub(r"p\{([\d.]+)\\linewidth\}", shrink_p, block)
    # Add \setlength{\tabcolsep}{3pt} after the first \centering
    if r"\tabcolsep" not in new:
        new = re.sub(
            r"(\\centering\s*\n)",
            r"\1\\setlength{\\tabcolsep}{" + str(TABCOLSEP_PT) + r"pt}\n",
            new, count=1,
        )
    return new


def fix_text(text: str) -> str:
    out = []
    pos = 0
    while True:
        bt = text.find(r"\begin{table}", pos)
        if bt == -1:
            out.append(text[pos:])
            break
        et = text.find(r"\end{table}", bt)
        if et == -1:
            out.append(text[pos:])
            break
        et_end = et + len(r"\end{table}")
        block = text[bt:et_end]
        # only act if there's a p{...} column
        if re.search(r"p\{[\d.]+\\linewidth\}", block):
            new_block = fix_table_block(block)
            out.append(text[pos:bt])
            out.append(new_block)
        else:
            out.append(text[pos:et_end])
        pos = et_end
    return "".join(out)


def main():
    n_files = 0
    for fname in ["section1_intro.tex", "section2_related.tex",
                  "section3_data.tex", "section4_method.tex",
                  "section5_css.tex", "section6.tex",
                  "section7_discussion.tex", "supplementary.tex"]:
        p = ROOT / fname
        if not p.exists():
            continue
        t = p.read_text()
        new = fix_text(t)
        if new != t:
            p.write_text(new)
            n_files += 1
            print(f"  fixed {fname}")
        else:
            print(f"  no change {fname}")
    print(f"\nUpdated {n_files} file(s).")


if __name__ == "__main__":
    main()
