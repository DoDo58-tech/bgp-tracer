# Paper — `docs/paper/`

LaTeX source for the SIGCOMM / IMC / NDSS submission:
**Joint Traffic--BGP Anomaly Attribution via Causal Sufficiency Scoring.**

## Files

| File | Purpose |
|---|---|
| `main.tex` | Top-level (acmart sigcomm) |
| `section1_intro.tex` | Introduction (motivation, contribution, headline result) |
| `section2_related.tex` | Related work |
| `section3_data.tex` | Data sources + v11 ground-truth construction |
| `section4_method.tex` | BGP Tracer two-phase architecture + Bayesian synthesis |
| `section5_css.tex` | Causal Sufficiency Scoring — math, bootstrap CI, permutation test |
| `section6.tex` | §6 evaluation (uses fig7/fig8/fig9 + per-event CSV) |
| `refs.bib` | Bibliography |
| `figs/` | All paper figures (PDF) |

## §6 figures

| Figure | Source script | CSV/JSONL input |
|---|---|---|
| `fig7_eval_overview.pdf` | `scripts/render_paper_figs.py::fig7_eval_overview` | `results/eval/per_event_v11.csv` |
| `fig8_per_cause.pdf` | `scripts/render_paper_figs.py::fig8_per_cause` | same |
| `fig9_event_direction_heatmap.pdf` | `scripts/render_paper_figs.py::fig9_event_direction_heatmap` | same |

## Compiling

The `acmart` class is required (SIGCOMM template). Install:

```bash
tlmgr install acmart   # if you use TeX Live
# or download from https://www.sigcomm.org/resources/acm-sig-communications-template
```

Then:

```bash
cd docs/paper
pdflatex main && bibtex main && pdflatex main && pdflatex main
# produces main.pdf
```

## Reproducing §6 numbers

```bash
cd /data/bgp_tracer
bash reproduce_eval.sh                # full run (needs .env + LLM + CF Radar)
bash reproduce_eval.sh --skip-phase1  # reuse existing results/quick/*.json
bash reproduce_eval.sh --dry-run      # print only
```

Numbers are guaranteed-stable to ±0.1% on the existing ground-truth;
see `results/eval/eval_audit.md` for the exact metric definitions and
the cross-check commands a reviewer can use to verify each row.

## Static checks

```bash
python scripts/check_paper.py
```

Checks that every `\input{}`, `\includegraphics{}`, `\cite{}`, and
`\ref{}` is satisfiable. Run this before committing any LaTeX edit.

## Updating §6

If the ground-truth CSV (`data_check/ground_truth_collection/final_balanced_dataset_v13.csv`)
or the ablation jsonl (`results/eval/hcaf_vs_baselines_v13.jsonl`)
changes:

1. Re-run `scripts/eval_hcaf_vs_baselines.py` (no LLM required).
2. Re-run `scripts/build_per_event_csv.py` (writes CSV).
3. Re-run `scripts/render_paper_figs.py` (regenerates fig7/8/9).
4. Update `section6.tex` numeric tables if the per-method summary shifts.
5. Append a `CHANGELOG.md` entry summarising the delta and the reason.

The `results/eval/eval_audit.md` document is the canonical place to
record cross-checks for any future number drift.
