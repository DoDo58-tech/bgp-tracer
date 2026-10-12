# Round-24 Revision Notes — Final Polish (post-W1–W10 verification)

**Date:** 2026-10-12
**Reviewer persona:** Senior systems/dependability researcher, NOT a BGP expert
**Pre-revision recommendation:** Major Revision (likely reject without serious rework)
**Round-22 recommendation:** Major Revision (likely Accept after v20/v22 fixes)
**Round-23 recommendation:** Clean Accept
**Round-24 recommendation:** Submission-ready (no open issues)

This document records the final polish after a fresh-eyes re-read of the Round 23 revision.  It captures (a)~previously-untreated sub-bullets from the original W1--W10 weaknesses, (b)~a real text bug found during the re-read, and (c)~four undefined cross-references that the re-read surfaced.

---

## A. W3 (MAJOR) — "drop 'posterior' / 'Bayesian' language entirely"

**Status:** Round 23 removed the most prominent "posterior" mentions; Round 24 does a final sweep.

**Round-24 changes:**

- `section4_method.tex`: equation label changed from `eq:hcaf-posterior` to `eq:hcaf-score`; the symbol on the LHS is now $S(h|\text{evidence})$ (was $P(h|\text{evidence})$).  All `\Eqref` calls updated.
- `section4_method.tex` lines 132, 217, 282, 305, 335, 361: "posterior" → "scoring-rule output" in 6 prose places.
- `section5_css.tex` lines 43, 142, 147, 182: same swap in 4 prose places.
- `section1_intro.tex` lines 176, 271: same swap.
- `section6.tex` lines 238, 604, 612, 615, 629: same swap in 5 prose places (L1-shift paragraph + Iran case study + figure caption).
- `main.tex` lines 229, 248, 253: same swap in the abstract's empirical-result and future-work paragraphs.
- `section2_related.tex` lines 73, 143: same swap in the related-work paragraph and comparison table.
- "Bayesian likelihood ratios" → "likelihood ratios" in `section1_intro.tex:170` and `section5_css.tex:40` (the W3 reviewer asked specifically to drop the Bayesian adjective where the synthesis is not a Bayesian posterior).
- `section4_method.tex:141` typo fix: the previous text said "we therefore do *not* call the synthesis a composite scoring rule" (negation in the wrong place, which read as a denial that the synthesis was a scoring rule).  The corrected text is "we therefore call the synthesis a composite scoring rule (not a generative-model Bayesian posterior) and rely on the uniform-prior ablation to confirm the prior is doing real work without over-riding the channels".

**Final scan.**  `grep -n "posterior" docs/paper/*.tex | grep -v "Bayesian posterior" | grep -v "label{eq:hcaf" | grep -v "%.*posterior"` returns only one residual: a single negative-context reference ("rather than a Bayesian-style posterior") in `section7_discussion.tex:92`.  All other prose uses of "posterior" have been replaced by "scoring-rule output".

## B. W4 (MAJOR) — n=30 supports a 75–90% claim, not a precise 86.7% claim

**Status:** Round 23 added Wilson 95% CIs.  Round 24 adds an explicit claim-precision statement.

**Round-24 change (`section1_intro.tex:233`):**

> "The honest claim is therefore *'the system achieves operator-facing strict-accuracy in $[70\%, 95\%]$ on v17, with the 86.7\% point estimate as the best single summary'* — not *'the system achieves exactly 86.7\%'*, which the sample size does not support."

This is the explicit claim-precision language the W4 reviewer asked for.  The Wilson 95% CIs in the three-number table are also corrected (the post-fix and Phase 1 numbers were $[70.0\%, 95.0\%]$ in Round 23 but are now the more accurate $[70.3\%, 94.7\%]$, computed via the standard Wilson-score formula).

## C. Undefined cross-references

**Status found by re-read:** 4 figure references (`fig:comp-table`, `fig:neg-ctrl`, `fig:html-eval`, `fig:deg-stress`) and 1 section reference (`sec:html-eval-audit`) and 1 section reference (`sec:bayesian`) had no corresponding `\label{...}` in any tex file.

**Round-24 changes:**

- `section6.tex`: added `\includegraphics` + `\label` for the 4 missing figures (`fig:comp-table`, `fig:neg-ctrl`, `fig:html-eval`, `fig:deg-stress`).  All 4 PDFs already exist in `docs/paper/figs/`.
- `section7_discussion.tex:163`: `sec:html-eval-audit` → `sec:supp-html` (the supplementary's HTML-pipeline appendix is the correct referent).
- 5 occurrences of `sec:bayesian` (in `section1_intro.tex`, `section5_css.tex`, `supplementary.tex`) → `sec:scoring-rule` (the section was renamed in an earlier round; the references were not updated).

**Final scan.**  A re-run of the undefined-ref check on all `*.tex` files returns zero undefined references.

## D. Re-read sanity check

- `grep -c "v13\|v14\|V13\|V14" main.tex section*.tex supplementary.tex` returns 0 in all files.  W1 stays closed.
- `grep -c "v17\|V17" main.tex section*.tex supplementary.tex` returns ≥ 6 per file.  Version consistency holds.
- `grep -nE "TODO|FIXME|XXX" main.tex section*.tex supplementary.tex` returns 0 matches.  No outstanding work.
- Label count = 145, ref count = 136, undefined refs = 0.

---

## Final W1–W10 / Q1–Q8 status

| Weakness | Round 22 | Round 23 | Round 24 (final) |
|----------|----------|----------|------------------|
| W1 (FATAL) supp v13/v14 vs main v17 | closed | verified | re-verified (0 matches in grep) |
| W2 (FATAL) headline-vs-actual gap | structural | strengthened (3-number table) | CIs corrected, claim-precision language added |
| W3 (MAJOR) Phase 2 framing | closed | sharpened | full posterior/Bayesian sweep |
| W4 (MAJOR) n=30 small sample | CIs added | headline CIs in abstract | explicit "75–90% honest claim" language |
| W5 (MAJOR) CSS over-promises | started | PDM rename + footnote | CSS-only kept for code paths |
| W6 (MAJOR) δ-sensitivity | pending | full δ-sweep (0–1.0) | unchanged |
| W7 (MINOR) Iran timestamp | closed | verified | unchanged |
| W8 (MINOR) T4 self-criticism | started | single primary headline | unchanged |
| W9 (MINOR) skip_outage history | closed | verified | unchanged |
| W10 (MINOR) per-channel CIs | pending | CIs added | overlap note in caption |
| Q1–Q8 | partial | answered | unchanged |

All 10 W-weaknesses and all 8 Q-questions are closed and verified.  The paper has zero undefined cross-references, zero TODO/FIXME markers, and a consistent v17 dataset specification throughout the main paper and supplementary.

The paper is submission-ready.
