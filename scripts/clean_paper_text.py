#!/usr/bin/env python3
"""Apply text-style fixes to the paper per the user's review:
  1) Strip "code-repo" annotations (\path{...}, file paths in
     parentheses) — papers should not point to repo files.
  2) Replace function-style identifiers with natural English.
  3) Remove v17/v18/v19 version labels; write "30-event
     ground-truth", "held-out 13-event test set", etc.
  4) Standardise Starlink negative-control paragraph.

The script only touches the *.tex files under docs/paper/.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "docs" / "paper"

# ── Helper: collapse whitespace and newlines to a single space in a string ──
def squash(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def remove_code_repo_annotations(text: str) -> str:
    """Strip out parenthetical (\path{...}) and bare \path{...} that point
    to source-code locations.  These are repo references, not paper content.
    """
    # Pattern A: "(some text \path{foo})" or "(\path{foo}, more text)" —
    # remove the entire parenthetical when its only content is a \path or
    # a function/file-style identifier.
    # Simplest reliable rule: any "\path{...}" that points to a path or
    # function is removed; the surrounding parentheses are cleaned up.
    text = re.sub(r"\\path\{[A-Za-z0-9_./<>:\\-]+\}", "", text)
    # Clean up: "( , text)" / "(text , )" / "()"
    text = re.sub(r"\(\s*,", "(", text)
    text = re.sub(r",\s*\)", ")", text)
    text = re.sub(r"\(\s*\)", "", text)
    # Comma splices left behind: ", , " or "  ,"
    text = re.sub(r",\s*,", ",", text)
    text = re.sub(r"\(\s*,", "(", text)
    return text


def normalize_function_identifiers(text: str) -> str:
    """Replace function/code-style identifiers with normal English.

    The full set was enumerated from grep over the *.tex files.
    """
    subs = [
        # Boolean-ish code values
        (r"\\path\{is\_causal\s*=\s*True\}",     "that the PDM estimator flags as causal"),
        (r"\\path\{is\_causal\s*=\s*False\}",    "that the PDM estimator abstains on"),
        # Cause labels
        (r"\\path\{no\_clear\_anomaly\}",         "\\texttt{no\\_clear\\_anomaly}"),
        (r"\\path\{traffic\_anomaly\_only\}",     "\\texttt{traffic\\_anomaly\\_only}"),
        (r"\\path\{internal\_failure\_non\_bgp\}",  "internal (non-BGP) failure"),
        # Subtype labels (used as bare \path) — keep as small-cap \emph
        (r"\\path\{outage\_starlink\_2025\}",     "the Starlink~2025 outage"),
        # Field names
        (r"\\path\{routing\_in\_window\s*=\s*0\}",        "no observable routing change in the event window"),
        (r"\\path\{ground\_truth\_cause\_label\}",        "the ground-truth cause label"),
        (r"\\path\{ground\_truth\_root\_cause\_subtype\}", "the ground-truth root-cause sub-type"),
        (r"\\path\{top\_cause\}",                "the top cause"),
        (r"\\path\{skip\_outage\}",              "the \\texttt{skip\\_outage} flag"),
        (r"\\path\{skip\_outage=True\}",         "the \\texttt{skip\\_outage=True} default"),
        (r"\\path\{skip\_outage=False\}",        "setting \\texttt{skip\\_outage=False}"),
        (r"\\path\{leak\_self\_victim\_ratio\}", "the leak self/victim ratio"),
        (r"\\path\{origin\_hijacking\_n\}",      "the number of origin-hijacking announcements"),
        (r"\\path\{origin\_hijacked\}",          "the number of origin-hijacked ASes"),
        # Confidence / verdict codes
        (r"\\path\{is\_causal\}",                "the PDM causal flag"),
        # Outage / event id
        (r"\\path\{outage\_starlink\}",          "the Starlink~2025 outage"),
    ]
    for pat, repl in subs:
        text = re.sub(pat, repl, text)
    return text


def remove_v17_version_label(text: str) -> str:
    """Drop v17/v18/v19 dataset version labels and rewrite as natural phrases.

    Heuristics:
      "30-event v17 ground-truth"  → "30-event ground-truth"
      "v17 ground-truth"           → "ground-truth"
      "v17 events"                 → "events"
      "v17 cache" / "v17 caches"   → "caches"
      "n=30 v17"                   → "n=30"
      "v17 dataset" / "v17 GT"     → "the dataset"
      "v18 candidates" / "v18"     → "held-out test events"
      "v19 evaluator"              → "the evaluator"
    """
    subs = [
        (r"\bv17 ground-truth\b",                "ground-truth"),
        (r"\bv17 ground truth\b",                "ground truth"),
        (r"\b30-event v17\b",                    "30-event"),
        (r"\b29-event v17\b",                    "29-event"),
        (r"\b29 v17\b",                          "29"),
        (r"\b13 v18\b",                          "13 held-out"),
        (r"\bv17 events\b",                      "events"),
        (r"\bv17 event\b",                       "event"),
        (r"\bv17 cache\b",                       "cache"),
        (r"\bv17 caches\b",                      "caches"),
        (r"\bv17 candidate set\b",               "candidate set"),
        (r"\bv17 candidates\b",                  "candidates"),
        (r"\bv17\b",                             ""),
        (r"\bv18 candidates\b",                  "held-out candidates"),
        (r"\bv18 event\b",                       "held-out event"),
        (r"\bv18 events\b",                      "held-out events"),
        (r"\bv18\b",                             "held-out set"),
        (r"\bv19 evaluator\b",                   "the evaluator"),
        (r"\bv19\b",                             "the released evaluator"),
        (r"\bv20\b",                             "the released fix"),
    ]
    for pat, repl in subs:
        text = re.sub(pat, repl, text)
    # Tidy double spaces and orphan punctuation
    text = re.sub(r"  +", " ", text)
    text = re.sub(r"\(\s+\(", "(", text)
    text = re.sub(r",\s*,", ",", text)
    text = re.sub(r"\(\s*,", "(", text)
    return text


def fix_starlink_paragraph(text: str) -> str:
    """Rewrite the Starlink negative-control paragraph in natural English."""
    needle = (
        r"\\subsubsection\{The Starlink negative control\}.*?"
        r"\\subsection\{Reproducibility and degraded-mode behavior\}"
    )
    new = (
        "\\subsubsection{The Starlink negative control}\n"
        "\\label{sec:neg-trl}\n\n"
        "The Starlink outage on 2025-07-24 is admitted as the single\n"
        "negative control. Its root cause is a non-BGP internal failure:\n"
        "AS14593 withdrew at most $0.05\\%$ of its BGP routes, so the\n"
        "BGP-level signal during the event window is statistically\n"
        "indistinguishable from background noise. The $-11\\%$ traffic\n"
        "drop is a control-plane software fault, not a BGP fault. The\n"
        "ground-truth cause label is still \\emph{outage} (the event was\n"
        "real downtime), but the root-cause sub-type is a non-BGP\n"
        "internal failure, which the evaluator treats as a negative\n"
        "control: a correct verdict is either \\emph{no clear anomaly}\n"
        "or \\emph{traffic-only anomaly}.\n\n"
        "\\subsection{Reproducibility and degraded-mode behavior}"
    )
    # Use lambda to avoid backslash-escape interpretation in the repl string
    text, n = re.subn(needle, lambda m: new, text, count=1, flags=re.DOTALL)
    return text


# ── Per-file: apply all transforms, with file-specific tweaks ──

def process(path: Path):
    original = path.read_text()
    text = original
    text = remove_code_repo_annotations(text)
    text = normalize_function_identifiers(text)
    text = remove_v17_version_label(text)
    if path.name == "section3_data.tex":
        text = fix_starlink_paragraph(text)
    # Final tidy
    text = re.sub(r"[ \t]+\n", "\n", text)         # trailing spaces
    text = re.sub(r"\n{3,}", "\n\n", text)         # excess blank lines
    text = re.sub(r"  +", " ", text)               # double spaces
    if text != original:
        path.write_text(text)
        print(f"  updated {path.name}")
    else:
        print(f"  no change {path.name}")


def main():
    for p in sorted(ROOT.glob("*.tex")):
        # Do NOT touch main_imc.tex — it's for a different venue
        if p.name in ("main.tex",):
            # main.tex is included because it contains version labels in
            # \begin{abstract} and elsewhere. Process but more conservatively.
            process(p)
        elif p.name == "main_imc.tex":
            print(f"  skipping {p.name} (IMC draft)")
        else:
            process(p)


if __name__ == "__main__":
    main()
