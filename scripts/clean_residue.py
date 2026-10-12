#!/usr/bin/env python3
"""Remove stray '\\end{tabular}%\n}' residue from previous broken
\\resizebox wraps.
"""
import re
from pathlib import Path

ROOT = Path("/data/bgp_tracer/docs/paper")

for fname in ["section1_intro.tex", "section2_related.tex",
              "section3_data.tex", "section4_method.tex",
              "section5_css.tex", "section6.tex",
              "section7_discussion.tex", "supplementary.tex"]:
    p = ROOT / fname
    if not p.exists():
        continue
    t = p.read_text()
    # Pattern: \end{tabular}%\n}\n  (the closing brace of resizebox)
    new = re.sub(r'\\end\{tabular\}%\n\}\n', r'\\end{tabular}\n', t)
    # Also catch: \end{tabular}%   (with no newline before })
    # This form is the ORIGINAL residue where my v1 wrap was:
    #   \end{tabular}\n%}\n
    # but the regex above already handles it
    if new != t:
        p.write_text(new)
        print(f"  cleaned {fname}")
    else:
        print(f"  no change {fname}")
