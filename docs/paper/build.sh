#!/bin/bash
# Build script for CoNEXT paper with sequential citation ordering.
set -e
cd "$(dirname "$0")"

# CoNEXT limits: at most 16 pages of main content before the references,
# an unlimited reference section, and at most 4 pages of appendix.
MAX_MAIN_PAGES=16
MAX_APPENDIX_PAGES=4

# Step 1: Clean old intermediates so a failed build can never leave a
# stale PDF behind that looks like a successful one.
rm -f *.bbl *.aux *.log *.out main.pdf

# Step 2: First tectonic compile (generates the .bbl)
echo "Running tectonic (first pass)..."
tectonic main.tex --keep-intermediates 2>&1 | grep -E "^error" && {
    echo "BUILD FAILED (first pass)"; exit 1;
}

if [ ! -f main.bbl ]; then
    echo "BUILD FAILED: main.bbl was not produced"; exit 1
fi

# Step 3: Reorder the bibliography into citation order
echo "Reordering bibliography..."
python3 reorder_bbl.py

# Step 4: Second tectonic compile (uses the reordered .bbl)
echo "Running tectonic (second pass)..."
tectonic main.tex 2>&1 | grep -E "^error" && {
    echo "BUILD FAILED (second pass)"; exit 1;
}

if [ ! -f main.pdf ]; then
    echo "BUILD FAILED: main.pdf was not produced"; exit 1
fi

# Step 5: Check the page budget.  The reference section is unlimited, so
# only the pages before it count against the main-content limit; the
# appendix has its own, smaller limit.
python3 - "$MAX_MAIN_PAGES" "$MAX_APPENDIX_PAGES" <<'PY'
import sys
import re
import pymupdf

max_main = int(sys.argv[1])
max_appendix = int(sys.argv[2])

doc = pymupdf.open("main.pdf")
pages = [p.get_text() for p in doc]

ref_page = next((i for i, t in enumerate(pages)
                 if re.search(r"(?m)^\s*References\s*$", t)), None)
appendix_page = next((i for i, t in enumerate(pages)
                       if re.search(r"(?m)^\s*A\s*Appendix\s*$", t)
                       or re.search(r"(?m)^\s*Appendix\s*$", t)), None)

main = ref_page if ref_page is not None else doc.page_count
appendix = doc.page_count - appendix_page if appendix_page is not None else 0

print(f"main.pdf: {doc.page_count} pages total, "
      f"{main} pages before the references, "
      f"{appendix} pages of appendix")

failures = []
if main > max_main:
    failures.append(
        f"main content is {main} pages, over the {max_main}-page limit")
if appendix > max_appendix:
    failures.append(
        f"appendix is {appendix} pages, over the {max_appendix}-page limit")

for f in failures:
    print(f"PAGE BUDGET EXCEEDED: {f}")
sys.exit(1 if failures else 0)
PY

echo "Done! main.pdf generated with sequential citations."
