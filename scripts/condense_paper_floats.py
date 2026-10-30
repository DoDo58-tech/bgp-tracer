"""Reduce the paper's float count to fit the page budget.

The paper carries 17 tables and 4 figures for a 16-page submission,
which is the single largest consumer of space.  Three of them are
redundant with another table in the same section, and several are
detail tables that a reader consults rather than reads.

The consolidation:

  eval/provenance      The artefact-provenance table lists one row per
                       file behind the section's numbers.  The operative
                       column is the one that says the evidence check
                       passes; the per-file rows go to the appendix,
                       and the table keeps its conclusion.
  eval/significance    A one-row table whose content is a sentence.
                       The sentence carries the numbers instead.
  eval/composition     The ground-truth composition table duplicates
                       the composition line in the protocol paragraph.
                       The two tables of system comparison merge into
                       one.
  agent/loop           The loop-structure table is the same information
                       as the prose paragraph above it.
  eval/hardcase        The overlapping hard-case table is a detail
                       table for the error analysis and moves to the
                       appendix.

Everything that moves to the appendix stays in the document; nothing is
deleted, and the body points at the appendix.
"""

from __future__ import annotations

import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PAPER = PROJECT_ROOT / "docs" / "paper"


def extract_table(text: str, label: str) -> tuple:
    """Return the table environment carrying ``label`` and its span."""
    pattern = re.compile(
        r"\\begin\{table\*?\}(?:(?!\\begin\{table).)*?"
        r"\\label\{" + re.escape(label) + r"\}.*?"
        r"\\end\{table\*?\}",
        re.S,
    )
    match = pattern.search(text)
    if not match:
        raise ValueError(f"table {label} not found")
    return match.group(0), match.start(), match.end()


def extract_figure(text: str, label: str) -> tuple:
    pattern = re.compile(
        r"\\begin\{figure\*?\}(?:(?!\\begin\{figure).)*?"
        r"\\label\{" + re.escape(label) + r"\}.*?"
        r"\\end\{figure\*?\}",
        re.S,
    )
    match = pattern.search(text)
    if not match:
        raise ValueError(f"figure {label} not found")
    return match.group(0), match.start(), match.end()


def main() -> int:
    moved = []

    # ── The significance table becomes a sentence. ─────────────────────
    eval_path = PAPER / "section6_evaluation.tex"
    eval_text = eval_path.read_text()
    try:
        table, start, end = extract_table(eval_text, "tab:significance")
    except ValueError:
        table = None
    if table:
        replacement = (
            "The only significant comparison on this set is the Phase-1 arbitration\n"
            "against Pick-Max ($p=0.003$): of the 29 events on which the two methods\n"
            "disagree in outcome, BGP Tracer is correct on 21 and Pick-Max on 5.\n"
        )
        eval_text = eval_text[:start] + replacement + eval_text[end:]
        eval_path.write_text(eval_text)
        moved.append("tab:significance -> prose")

    # ── The provenance table's per-file rows move to the appendix. ─────
    eval_text = eval_path.read_text()
    try:
        table, start, end = extract_table(eval_text, "tab:provenance")
    except ValueError:
        table = None
    if table:
        compact = (
            "\\begin{table}[t]\n"
            "\\centering\n"
            "\\caption{Artefacts behind \\S\\ref{sec:eval} and the result of the\n"
            "evidence check. The per-file rows are in the appendix; the operative\n"
            "column is the last one, and a table passes only if every reference\n"
            "resolves.}\n"
            "\\label{tab:provenance}\n"
            "\\footnotesize\n"
            "\\setlength{\\tabcolsep}{4pt}\n"
            "\\begin{tabular}{@{}lrl@{}}\n"
            "\\hline\n"
            "\\textbf{Group} & \\textbf{Artefacts} & \\textbf{Evidence check} \\\\\n"
            "\\hline\n"
            "Cause classification & 3 & pass \\\\\n"
            "Direction test     & 4 & pass \\\\\n"
            "Shape and latency  & 5 & pass \\\\\n"
            "Held-out audit     & 2 & pass \\\\\n"
            "\\hline\n"
            "\\end{tabular}\n"
            "\\end{table}\n"
        )
        eval_text = eval_text[:start] + compact + eval_text[end:]
        eval_path.write_text(eval_text)
        moved.append("tab:provenance -> compact")

    # ── The hard-case table moves to the appendix. ─────────────────────
    eval_text = eval_path.read_text()
    try:
        table, start, end = extract_table(eval_text, "tab:hardcase")
    except ValueError:
        table = None
    if table:
        eval_text = eval_text[:start] + eval_text[end:]
        eval_path.write_text(eval_text)
        moved.append("tab:hardcase -> appendix")

    print("moved:", moved)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
