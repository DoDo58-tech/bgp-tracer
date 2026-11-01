"""Where the paper's pages go.

The CoNEXT submission has a 16-page limit on the main content, with
the references and a four-page appendix outside it.  Cutting a paper
to length is a mechanical exercise once the space is accounted for, and
this script produces that accounting: for every section and every
float, the number of characters of prose and the number of characters
of table and figure code.

Floats are what actually cost pages, and they are also the part of a
paper a reader is most likely to want kept.  The script therefore
reports the two separately, so a cut can be aimed at prose first.

It also reports the page at which each section starts, read from the
compiled PDF, so that the cuts can be prioritised by where they
actually pay.

Writes results/eval/paper_length_budget.json.
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


def strip_comments(text: str):
    text = re.sub(r"(?<!\\)%.*", "", text)
    return text


def split_floats(text: str):
    """Separate float environments from the prose around them."""
    float_re = re.compile(
        r"\\begin\{(table|figure)\*?\}.*?\\end\{\1\*?\}", re.S
    )
    floats = float_re.findall(text)
    float_chars = sum(len(m.group(0)) for m in float_re.finditer(text))
    prose = float_re.sub("", text)
    return prose, float_chars, len(floats)


def count_words(text: str):
    text = re.sub(r"\\[a-zA-Z]+\*?(\[[^\]]*\])?", " ", text)
    text = re.sub(r"[{}$&\\~^_]", " ", text)
    return len([w for w in text.split() if any(ch.isalnum() for ch in w)])


def pdf_page_map():
    """The page each section heading lands on, read from the PDF."""
    try:
        import pypdf
    except ImportError:
        return {}
    pdf = PAPER / "main.pdf"
    if not pdf.exists():
        return {}
    reader = pypdf.PdfReader(str(pdf))
    pages = {}
    for index, page in enumerate(reader.pages, 1):
        text = page.extract_text() or ""
        for match in re.finditer(
            r"^\s*(\d+(?:\.\d+)*)\s+([A-Z][A-Za-z][^\n]{4,60})$", text, re.M
        ):
            pages.setdefault(match.group(1).strip(), index)
    return pages


def pdf_page_budget():
    """The measured page split, read from the compiled PDF.

    The submission limit counts the pages before the references; the
    appendix has its own, smaller limit.  Reporting the measured split
    is what makes the budget checkable rather than aspirational.
    """
    pdf = PAPER / "main.pdf"
    if not pdf.exists():
        return {}
    try:
        import pymupdf
    except ImportError:
        return {}
    doc = pymupdf.open(str(pdf))
    pages = [p.get_text() for p in doc]
    ref_page = next((i for i, t in enumerate(pages)
                     if re.search(r"(?m)^\s*References\s*$", t)), None)
    appendix_page = next((i for i, t in enumerate(pages)
                           if re.search(r"(?m)^\s*A\s*Appendix\s*$", t)
                           or re.search(r"(?m)^\s*Appendix\s*$", t)), None)
    main_pages = ref_page if ref_page is not None else doc.page_count
    return {
        "total_pages": doc.page_count,
        "main_content_pages": main_pages,
        "reference_pages": (appendix_page - ref_page)
        if (appendix_page is not None and ref_page is not None) else 0,
        "appendix_pages": doc.page_count - appendix_page
        if appendix_page is not None else 0,
        "within_budget": main_pages <= 16
        and (doc.page_count - appendix_page if appendix_page is not None else 0) <= 4,
    }


def main():
    page_map = pdf_page_map()
    rows = []
    for name in SECTIONS:
        path = PAPER / name
        if not path.exists():
            continue
        raw = path.read_text()
        text = strip_comments(raw)
        prose, float_chars, n_floats = split_floats(text)
        rows.append({
            "section": name,
            "chars_total": len(text),
            "chars_prose": len(prose),
            "chars_floats": float_chars,
            "n_floats": n_floats,
            "words_prose": count_words(prose),
        })

    total_prose = sum(r["chars_prose"] for r in rows)
    total_float = sum(r["chars_floats"] for r in rows)

    out = {
        "sections": rows,
        "totals": {
            "chars_prose": total_prose,
            "chars_floats": total_float,
            "words_prose": sum(r["words_prose"] for r in rows),
            "n_floats": sum(r["n_floats"] for r in rows),
        },
        "page_map": page_map,
        "measured": pdf_page_budget(),
        "target": {
            "main_content_pages": 16,
            "appendix_pages_allowed": 4,
            "references": "unlimited",
        },
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(out, indent=1, default=str))

    print(f"{'section':32s} {'words':>7s} {'prose':>8s} {'floats':>8s} {'n':>4s}")
    for r in rows:
        print(f"{r['section']:32s} {r['words_prose']:>7d} "
              f"{r['chars_prose']:>8d} {r['chars_floats']:>8d} "
              f"{r['n_floats']:>4d}")
    print(f"{'TOTAL':32s} {out['totals']['words_prose']:>7d} "
          f"{total_prose:>8d} {total_float:>8d} "
          f"{out['totals']['n_floats']:>4d}")
    print()
    print("measured:", json.dumps(out["measured"], indent=1))
    print("page map:", json.dumps(page_map, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
