#!/usr/bin/env python3
"""Safely remove all \\resizebox wrappers from .tex files.
Strategy: find every \\resizebox, then bracket-count braces to find
the end of the *third* argument, then drop the whole construct.
"""
import re
from pathlib import Path

ROOT = Path("/data/bgp_tracer/docs/paper")


def remove_resizebox(text: str) -> str:
    out = []
    i = 0
    while i < len(text):
        idx = text.find(r"\resizebox", i)
        if idx == -1:
            out.append(text[i:])
            break
        out.append(text[i:idx])
        # Find the end of the third argument
        j = idx + len(r"\resizebox")
        # Skip whitespace
        while j < len(text) and text[j].isspace():
            j += 1
        # Three mandatory args, each in { ... }
        for arg_idx in range(3):
            if j >= len(text) or text[j] != "{":
                # Malformed; just stop
                out.append(text[idx:])
                return "".join(out)
            depth = 0
            k = j
            while k < len(text):
                ch = text[k]
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        k += 1
                        break
                k += 1
            if depth != 0:
                # Malformed
                out.append(text[idx:])
                return "".join(out)
            j = k
            if arg_idx < 2:
                while j < len(text) and text[j].isspace():
                    j += 1
        i = j
    return "".join(out)


def main():
    for fname in ["section1_intro.tex", "section2_related.tex",
                  "section3_data.tex", "section4_method.tex",
                  "section5_css.tex", "section6.tex",
                  "section7_discussion.tex", "supplementary.tex"]:
        p = ROOT / fname
        if not p.exists():
            continue
        t = p.read_text()
        new = remove_resizebox(t)
        if new != t:
            p.write_text(new)
            print(f"  cleaned {fname}")
        else:
            print(f"  no change {fname}")


if __name__ == "__main__":
    main()
