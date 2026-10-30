"""Move the hard-case accuracy table into the appendix.

The table reports strict Top-1 accuracy on four overlapping subsets of
the 29 curated events.  It is a detail table for the error analysis:
the body states the conclusion in prose and the table is the working
behind it.  Moving it to the appendix keeps the body within the page
budget and keeps the table in the document.
"""

from __future__ import annotations

import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PAPER = PROJECT_ROOT / "docs" / "paper"
EVAL = PAPER / "section6_evaluation.tex"
APPENDIX = PAPER / "appendix.tex"


def main() -> int:
    text = EVAL.read_text()
    pattern = re.compile(
        r"\\begin\{table\*?\}(?:(?!\\begin\{table).)*?"
        r"\\label\{tab:robustness\}.*?"
        r"\\end\{table\*?\}\n",
        re.S,
    )
    match = pattern.search(text)
    if not match:
        print("tab:robustness not found")
        return 1
    table = match.group(0)
    EVAL.write_text(text[:match.start()] + text[match.end():])

    appendix = APPENDIX.read_text()
    appendix += (
        "\n\\subsection{Hard-case accuracy subsets}\n"
        "\\label{app:hardcase}\n\n"
        "The table behind the regime discussion in the error analysis. The\n"
        "subsets overlap, so the event counts do not sum to 29.\n\n"
        + table
    )
    APPENDIX.write_text(appendix)
    print(f"moved tab:robustness to the appendix ({len(table)} chars)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
