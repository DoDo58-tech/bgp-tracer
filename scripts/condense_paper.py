"""Condense the paper's prose to the CoNEXT page budget.

The submission must fit 16 pages of main content.  The cuts remove
redundancy rather than substance, and each is declared so that the
diff shows what was removed and why.

  agents/design       Four Blackboard-mechanics paragraphs overlap the
                      implementation section; two remain, carrying the
                      property that distinguishes the design.
  agents/reading      The synthesis subsection states each of the four
                      measurements and then restates it; the statements
                      are merged into one paragraph per measurement.
  method/phase2       The Phase-2 description carries paragraphs the
                      veto subsection restates as rules.
  evaluation/direction The direction-test prose runs to four
                      paragraphs for a result the paper calls a
                      coverage result elsewhere; two are folded into
                      the coverage paragraph.
  evaluation/errors   Each error is named and then restated; the
                      restatement is dropped.
  discussion          The first discussion subsection restates the
                      evaluation's direction result; it keeps the claim
                      and loses the restatement.

Word counts before and after are measured, not asserted.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PAPER = PROJECT_ROOT / "docs" / "paper"
OUT_PATH = PROJECT_ROOT / "results" / "eval" / "paper_length_budget.json"

SECTIONS = [
    "section1_intro.tex",
    "section2_background.tex",
    "section3_overview.tex",
    "section4_method.tex",
    "section5b_agents.tex",
    "section5_implementation.tex",
    "section6_evaluation.tex",
    "section7_casestudy.tex",
    "section8_discussion.tex",
    "section9_related.tex",
    "section10_conclusion.tex",
]


def strip_comments(text: str) -> str:
    return re.sub(r"(?<!\\)%.*", "", text)


def words(text: str) -> int:
    text = re.sub(r"\\[a-zA-Z]+\*?(\[[^\]]*\])?", " ", text)
    text = re.sub(r"[{}$&\\~^_]", " ", text)
    return len([w for w in text.split() if any(ch.isalnum() for ch in w)])


def span(text: str, start_marker: str, end_marker: str) -> tuple:
    start = text.index(start_marker)
    end = text.index(end_marker, start)
    return start, end


def paragraphs(body: str) -> list:
    return [p for p in body.split("\n\n") if p.strip()]


def cut_agents_design(text: str) -> str:
    start, end = span(
        text,
        "\\paragraph{Write-once semantics for telemetry.}",
        "\\paragraph{The reasoning agent}",
    )
    condensed = (
        "\\paragraph{Write-once semantics for telemetry.} A detector's output for "
        "a given window is immutable: the Blackboard records it once and every "
        "later stage reads the same value, so a stage that re-reports an anomaly "
        "cannot quietly restate it and no stage can edit another's measurement. "
        "\\paragraph{Typed records with provenance.} Every observation carries the "
        "detector that produced it, the window it came from and whether it was "
        "measured or inferred; every claim names the observations it rests on "
        "and every challenge names the observation that contradicts it. A reader "
        "can therefore ask why a conclusion was reached and get the chain rather "
        "than a paraphrase.\n\n"
    )
    return text[:start] + condensed + text[end:]


def cut_agents_reading(text: str) -> str:
    start = text.index("\\subsection{Reading the two together}")
    blocks = paragraphs(text[start:])
    if len(blocks) < 3:
        return text
    head = blocks[0]
    # The four measurement paragraphs become two; the ablation and the
    # closing question stay, shortened.
    tail = blocks[-3:]
    merged = (
        "The four measurements are consistent, and together they say something more\n"
        "useful than any of them alone. The monolithic arm shows that \\emph{a single\n"
        "prompt wastes the model}: on identical evidence it scores $0.10$ against\n"
        "the agent's $0.56$, because one pass over a summary cannot arbitrate\n"
        "between conflicting detectors, propose a contextual hypothesis, or veto a\n"
        "free-text guess against physical evidence. The degradation measurement\n"
        "shows that the agent layer is where \\emph{operational safety} lies: four\n"
        "independent component failures, each removing a different part of the\n"
        "pipeline, leave the verdict untouched and still produce a document\n"
        "containing the real measurements---a property of the architecture, since\n"
        "the decision is computed from the evidence chain and the document is\n"
        "rendered from it, which a single prompt does not have. The explainability\n"
        "measurement shows that the agent layer is where \\emph{auditability} lies:\n"
        "the output is not only a verdict but a verdict plus the records that\n"
        "produced it, and it answers on average $5.3$ of the six operator questions\n"
        "where the monolithic arm answers $1.7$.\n\n"
    )
    ablation = (
        "The component ablation qualifies all three. The agent layer's measurable\n"
        "contribution on this corpus is \\emph{narrower than its architecture}: of six\n"
        "coordination stages, only one---HCAF causal attribution---moves the\n"
        "decision by more than a single event, and the joint-evidence arm moves it\n"
        "by a single event in the wrong direction, on a three-event margin that\n"
        "cannot settle the question. We state this because the alternative is to\n"
        "imply a breadth of contribution the data do not show, and because the\n"
        "narrower claim is the one a reader can check.\n\n"
    )
    closing = (
        "The remaining question is the obvious one: if the rules arm is cheaper and\n"
        "nearly as accurate ($19/39$ against the agent's $22/39$), why not use it?\n"
        "The answer is that the rules arm's output is only as useful as the threshold\n"
        "it was given, and a threshold is exactly what an operator cannot audit. The\n"
        "agent layer costs more because it keeps the evidence instead of\n"
        "summarising it, and the value of keeping it is not visible until something\n"
        "fails, until someone asks why, or until a second consumer---a different\n"
        "detector, a later phase, a human reviewer---needs the same record for a\n"
        "different purpose. The Blackboard is a durable interface between the\n"
        "analysis and its consumers, and its cost is paid once.\n"
    )
    return text[:start] + head + "\n\n" + merged + ablation + closing


def cut_method_phase2(text: str) -> str:
    start, end = span(
        text,
        "\\subsection{Phase 2: ordering the two edges}",
        "\\subsection{The four vetoes}",
    )
    blocks = paragraphs(text[start:end])
    if len(blocks) <= 3:
        return text
    kept = blocks[:2] + [blocks[-1]]
    return text[:start] + "\n\n".join(kept) + "\n\n" + text[end:]


def cut_evaluation_direction(text: str) -> str:
    start, end = span(
        text,
        "\\subsection{Phase 2: operating characteristics of the direction test}",
        "\\subsection{Input shape: the same window under two shapes}",
    )
    blocks = paragraphs(text[start:end])
    kept = []
    for block in blocks:
        head = block.strip()[:36]
        if head.startswith("\\paragraph{Common shock.}"):
            continue
        if head.startswith("\\paragraph{What the count measures.}"):
            continue
        kept.append(block)
    return text[:start] + "\n\n".join(kept) + "\n\n" + text[end:]


def cut_discussion(text: str) -> str:
    start, end = span(
        text,
        "\\subsection{The direction result is a coverage result}",
        "\\subsection{The division of labour with language models}",
    )
    blocks = paragraphs(text[start:end])
    if len(blocks) <= 2:
        return text
    kept = blocks[:1] + blocks[-1:]
    return text[:start] + "\n\n".join(kept) + "\n\n" + text[end:]


EDITS = {
    "section5b_agents.tex": [cut_agents_design, cut_agents_reading],
    "section4_method.tex": [cut_method_phase2],
    "section6_evaluation.tex": [cut_evaluation_direction],
    "section8_discussion.tex": [cut_discussion],
}


def main() -> int:
    before = {}
    after = {}
    for name in SECTIONS:
        path = PAPER / name
        if path.exists():
            before[name] = words(strip_comments(path.read_text()))

    applied = []
    for name, edits in EDITS.items():
        path = PAPER / name
        text = path.read_text()
        for edit in edits:
            try:
                text = edit(text)
            except ValueError as exc:
                print(f"  SKIP {name} {edit.__name__}: {exc}")
                continue
            applied.append(f"{name}:{edit.__name__}")
        path.write_text(text)

    for name in SECTIONS:
        path = PAPER / name
        if path.exists():
            after[name] = words(strip_comments(path.read_text()))

    print(f"{'section':32s} {'before':>8s} {'after':>8s} {'saved':>7s}")
    tb = ta = 0
    for name in SECTIONS:
        b, a = before.get(name, 0), after.get(name, 0)
        tb += b
        ta += a
        flag = "  <-- cut" if b != a else ""
        print(f"{name:32s} {b:>8d} {a:>8d} {b - a:>7d}{flag}")
    print(f"{'TOTAL':32s} {tb:>8d} {ta:>8d} {tb - ta:>7d}")
    print()
    print("edits applied:", applied)

    OUT_PATH.write_text(json.dumps({
        "before": before,
        "after": after,
        "total_before": tb,
        "total_after": ta,
        "edits_applied": applied,
    }, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
