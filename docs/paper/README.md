# Paper — `docs/paper/`

LaTeX source for the DSN 2027 submission (v19 cycle, 2026-10-10):

**Dependable Joint Attribution of Internet Anomalies: A
Deterministic, Causal-Anchored Engine for BGP and Traffic
Anomaly Co-Root-Cause Analysis**

**Headline number:** Phase-1 deterministic root-cause arbitration
is strict-correct on **$\frac{26}{30}$ (86.7\%)** events overall
and **$\frac{26}{28}$ (92.9\%)** excluding the negative control on
the 30-event v17 ground-truth --- a **$+16.7$~percentage-point**
gain over the v18 pre-optimization baseline.

## Target venue: DSN 2027

- **Abstract deadline: 2026-11-25** (one week before paper deadline)
- **Paper deadline: 2026-12-02**
- **Page limit: 11 pages** (text + figures count; references free)
- **Format: IEEE Computer Society 8.5×11″ two-column, 10pt font, 12pt leading**
- **Template: `IEEEtran` with `[conference,compsoc,10pt]` options**
- **Double-blind: anonymized, no acknowledgments, no self-citation**

## Files

| File | Purpose | Approx.\ size |
|---|---|---|
| `main.tex` | Top-level (IEEEtran conf/compsoc/10pt) | 6.5K chars |
| `section1_intro.tex` | Introduction (motivation, three dependability properties, headline 86.7\%) | 7.8K chars |
| `section2_related.tex` | Related work (4 buckets + Table I) | 6.0K chars |
| `section3_data.tex` | Data sources + v17 ground-truth (6 invariants, NC, degraded modes) | 6.3K chars |
| `section4_method.tex` | BGP Tracer two-phase architecture + Phase-1 arbitration | 10.0K chars |
| `section5_css.tex` | CSS summary (full math in supplementary) | 3.3K chars |
| `section6.tex` | §6 evaluation (26/30 headline, per-cause, 4-miss audit, fixes, case study) | 8.9K chars |
| `section7_discussion.tex` | Discussion + 4 threats to validity + reproducibility | 4.9K chars |
| `refs.bib` | Bibliography (23 entries) | |
| `figs/` | All paper figures (PDF) | 1 used (fig1), 12 spare |

**Total: ~53K characters, estimated 9.6-11 pages (within 11-page DSN limit).**

## Uploading to Overleaf

1. Create a new Overleaf project from "Blank paper" (do \emph{not} use ACM's official template, our preamble is self-contained with `IEEEtran`).
2. In the Overleaf project menu, set **Compiler** to `pdfLaTeX` (the default).
3. Upload these files into the project root (do \emph{not} put them in a subfolder):
   ```
   main.tex
   section1_intro.tex
   section2_related.tex
   section3_data.tex
   section4_method.tex
   section5_css.tex
   section6.tex
   section7_discussion.tex
   refs.bib
   ```
4. Create a `figs/` folder inside the project and upload the existing `figs/*.pdf`
   files. Only `fig1_architecture.pdf` is referenced in the main paper body; the
   other figures are in the supplementary material.
5. Click **Recompile** --- Overleaf will run `pdflatex` three times
   automatically to resolve the cross-references and the bibliography.

If `IEEEtran` is missing in Overleaf, the project will fail to
compile. In the Overleaf project menu, **Logs** will show
`LaTeX Error: File 'IEEEtran.cls' not found`. To fix, in the
project menu select **Settings → Compiler → TeX Live version →
2023 (or newer)** --- `IEEEtran` is bundled with TeX Live 2023
and later. If still missing, download `IEEEtran.cls` from
\url{https://www.ctan.org/pkg/ieeetran} and upload it to the
project root.

## Compiling locally (if you have TeX Live)

```bash
cd docs/paper
pdflatex main && bibtex main && pdflatex main && pdflatex main
# produces main.pdf
```

## Reproducing the §6 numbers

```bash
cd /data/bgp_tracer
python3 scripts/rebuild_v18_subprocess.py    # 29/30 cache builds
python3 scripts/cache_only_evaluation_v18.py  # produces
                                               # results/cache_predicted_v18.csv
```

The expected output:

```
=== v19 cache-based deterministic evaluation (no LLM) ===
All events:    26/30 = 86.7%
Excl neg ctl:  26/28 = 92.9%
```

## Double-blind checklist (DSN requirement)

- [x] No author list, no affiliations, no email in main.tex
  (anonymized as "Anonymous Authors / Anonymous Institution")
- [x] No `\begin{acks}` section
- [x] No "This work was supported by" statement
- [x] All self-citations rewritten as third-person
  ("the prior \hcaf{}" → `\cite{hcaf-v1}`; bib entry lists
  "Anonymous" author)
- [x] No specific GitHub URLs that would identify authors
  (replaced with "released artifact")
- [x] For camera-ready: replace anonymized author block
  with real author list using
  `\IEEEauthorblockN{...} \IEEEauthorblockA{...}` and
  uncomment the `\IEEEcompsocitemizethanks` macro in
  main.tex (instructions in comments).

## What changed in this revision (v18 → v19 → DSN 2027)

- **Target venue:** NDSS 2026 / SIGCOMM 2026 (A, missed) →
  **DSN 2027 (B)**.
- **Headline number:** 29/29 HCAF direction (v14) →
  26/30 root-cause classification (v18/v19), $+16.7$~pp
  over v18 pre-optimization baseline.
- **Template:** ACM `acmart` (sigcomm) → IEEE `IEEEtran`
  (conference, compsoc, 10pt).
- **Story arc:** "Causal attribution" →
  "**Dependable joint attribution**" (interpretabili-
  ty, reproducibility, graceful degradation).
- **Section 5 (CSS) compressed** to a summary; full
  derivation moved to supplementary (DSN 11-page limit).
- **Phase-1 10 fixes:** summarised in §6 with the
  "principled, observable, no ground-truth leakage"
  framing; full before/after analysis in supplementary.
- **Negative control added** (Starlink 2025); affects
  "all events" but not "excl.\ NC" strict-accuracy.
- **Degraded-mode behavior** (graceful degradation) is a
  first-class design priority, not an afterthought.
- **Threats to validity** structured as 4 categories
  (T1 dataset, T2 over-fitting, T3 phase mixing,
  T4 generalisation).
- **Reproducibility** explicit: every number is
  regenerable by one shell command; the single no-cache
  miss is explainable, not catastrophic.

## Updating the paper

If the ground-truth CSV
(`data_check/ground_truth_collection/final_balanced_dataset_v17.csv`)
or the cache evaluator (`scripts/cache_only_evaluation_v18.py`)
changes:

1. Re-run `scripts/cache_only_evaluation_v18.py` (no LLM required).
2. Update `section6.tex` numeric tables if the per-cause summary shifts.
3. Re-run static checks (see below) to verify consistency.
4. Append a CHANGELOG entry summarising the delta and the reason.

The `docs/paper/STATUS_REPORT_V18_20261010.md` document is the
canonical place to record the algorithmic reasoning behind any
future number drift.
