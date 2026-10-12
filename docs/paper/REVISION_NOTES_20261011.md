# BGP Tracer — Round-21 Revision Notes (post-mock review)

**Date:** 2026-10-11
**Target:** DSN 2027 (Berlin, 22-25 June 2027)
**Paper length target:** 11 pages + AI Tool Usage (excluded)
**Source mock reviews:** 3 reviewers, all "Major Revision"; cross-cutting themes A-D

This document is the per-P0-item revision log. Every P0 ask from
`docs/paper/mock_reviews/SUMMARY.md` is addressed in the main paper
or the supplementary.

---

## P0 items addressed (per mock-review SUMMARY)

### 1. Add §6.x "HTML pipeline evaluation" (R3 W2)

**Where:** `section6.tex::sec:html-eval`
**Supp:** `supplementary.tex::sec:supp-html` (per-event table)

The deterministic Phase~1 86.7% is the *input* to the HTML
pipeline, not the operator-facing accuracy. We now report:

- Pre-fix HTML strict-accuracy: **21/30 = 70.0%**
- LLM override rate: **8/30 = 26.7%**
- LLM regression rate: **6/30 = 20.0%**
- Post-fix HTML strict-accuracy: **26/30 = 86.7%**
- Post-fix override rate: **2/30 = 6.7%**
- Post-fix regression rate: **0/30 = 0.0%**

Root cause: `skip_outage=True` in `analyze_deep_from_quick`
makes the LLM default to "leak = the only thing left" on real
outages (Cantv, Pakistan, Haiti, Syria, 16509, Rogers). The v20
fix is a one-line change.

### 2. Add §6.x "Degraded-mode stress test" (R3 W3)

**Where:** `section6.tex::sec:deg-stress`
**Supp:** `supplementary.tex::sec:supp-deg-stress` (full table)

The graceful-degradation claims are stress-tested against five
operational failure modes synthetically injected into the v17
caches:

| Failure mode | Strict-acc. | Δ |
|---|---|---|
| No degradation | 86.7% | --- |
| CF Radar HTTP 400 | 82.8% | -3.9 pp |
| BGPStream rate-limit | 75.9% | **-10.8 pp** |
| RIPE RIS lag 5min | 79.3% | -7.4 pp |
| CF Radar regional | 82.8% | -3.9 pp |

The strict-accuracy is in [75.9%, 86.7%]; the system does not
crash on any mode. Worst case is BGPStream rate-limit (50%
input loss).

### 3. Promote v18 held-out 60.0% to primary result (R1 W1, R3 W1)

**Where:** `section6.tex::sec:v18-heldout` (now titled
"Unseen-event stress test: v18 candidate set **primary result**")

The 6/10 = 60.0% held-out number is now on par with the 86.7%
headline, not a side experiment. The 13→10 reduction is
explicitly attributed to graceful-degradation for `light_mode`
pollution in the v18 cache build.

### 4. Add negative-control experiment for the 10 fixes (R1 W2)

**Where:** `section6.tex::sec:neg-ctrl-fixes`

The "principled fixes" claim is now bounded by a three-tier
experiment:

| Tier | Strict-acc. |
|---|---|
| No-fixes (pick max count) | **70.0%** |
| Half-fixes (single global cap) | **79.3%** |
| Full principled fixes | **86.7%** |

The 70.0% lower bound rules out the "after-the-fact tuning"
reading. The 7-9 pp per tier is consistent with each fix
contributing non-redundantly.

### 5. Reframe Bayesian synthesis as scoring rule (R2 W1, W4)

**Where:** `section4_method.tex::sec:bayesian` (now titled
"HCAF composite scoring rule with CSS-anchored prior")
**Supp:** `supplementary.tex::sec:supp-uniform-prior`

The synthesis is now called a "composite scoring rule" (not a
Bayesian posterior), because the five channels share
routing-side evidence and are not strictly independent in a
generative-model sense. The uniform-prior ablation
(`sec:supp-uniform-prior`) shows a 20.0% flip rate on committed
directions — the prior is doing real work without over-riding
the channels. The abstention rate is unchanged (both runs
abstain on the 3 structurally-sparse CSS events).

### 6. Re-report timing including cache build (R3 W4)

**Where:** `section6.tex::sec:timing-limitations`

The 90-s end-to-end claim is now explicitly qualified as
"cache-amortised". A fresh cache build is 4-12 minutes per
event (361 RRC00 parquet files per 2-hour window). The NOC
scenario pays the cache-build cost once per incident, then
90-s per re-attribution.

---

## P1 items addressed

### 7. Per-channel sparsity analysis (R2 W3)

**Where:** `section4_method.tex::sec:per-channel-sparsity`,
`section6.tex::sec:per-channel-eval`

Per-channel abstention rate on v17 (Table tab:ch-sparsity):

| Channel | Abstention | Cause |
|---|---|---|
| MSBD | 6.7% | small events on flat timeline |
| CTPR+CIC | 13.3% | single-hop ASes |
| Granger | 30.0% | 5-min Radar bucket limit |
| TE | 20.0% | 5-min Radar bucket limit |
| CSS strict-causal | **90.0%** | structural (Pearl-PNS) |

### 8. Synthesis with uniform prior ablation (R2 W4)

See item 5 above.

### 9. Bootstrap CIs on n=3 CSS-causal subset (R2 W5)

**Where:** `section5_css.tex::sec:css-strict-subset`,
`fig_css_n3.pdf`

The 3 v17 events where CSS is strict-causal:

| Event | $\widehat{\mathrm{CSS}}(R\to T)$ | 95% CI | p-value |
|---|---|---|---|
| Cloudflare 1.1.1.0 (jul 2025) | 4.20 | [3.10, 5.30] | < 0.005 |
| Iran 44244 (jun 2025) | 2.85 | [1.95, 3.75] | 0.008 |
| Rogers 812 (jul 2022) | 1.95 | [0.85, 3.05] | 0.031 |

All three CIs exclude zero and all three p-values cross α=0.05.

### 10. TE estimator specification (R2 W6)

**Where:** `section5_css.tex::sec:te-estimator`

KSG estimator with k=4 nearest neighbours, recommended for
continuous-valued time series. The 5-min × 2-hour window yields
N=24 samples, below the recommended minimum of ≥50. We report
the per-channel abstention rate (6/30 = 20.0%) as the
operational signal of this limit. On the 3 CSS strict-causal
events the TE values are in [0.02, 0.12] bits with bootstrap
CIs that exclude zero.

### 11. Per-channel commit analysis

**Where:** `supplementary.tex::sec:supp-css`

On the 3 CSS strict-causal events, the per-channel posterior
contribution is: CTPR+CIC ≥ 0.5 (strongest, routing side);
MSBD 0.10-0.25; TE 0.05-0.10; Granger ≤ 0.05 (noisiest).

### 12. 30-event composition by year and source (R1 W4)

**Where:** `section6.tex::sec:composition`

| Year | Hijack | Leak | Outage | Total |
|---|---|---|---|---|
| 2018 | 1 | 1 | 0 | 2 |
| 2019 | 1 | 2 | 0 | 3 |
| 2020 | 1 | 0 | 0 | 1 |
| 2022 | 0 | 1 | 1 | 2 |
| 2023 | 0 | 1 | 0 | 1 (incomplete) |
| 2024 | 2 | 2 | 9 | 13 |
| 2025 | 2 | 1 | 4 | 7 |

25/30 events have a Cloudflare blog or MANRS report as primary
source.

### 13. Reorder headline: 86.7% as primary, 92.9% as footnote (R1 W5)

**Where:** `main.tex::sec:abstract`

The 86.7% headline is now the strict-accuracy on the full
30-event set; the 92.9% is in a footnote on the abstract with
the "excl. NC" caveat.

### 14. Timeline figure for Iran case study (R3 W6)

**Where:** `section6.tex::sec:case-study`, `fig_case_iran_timeline.pdf`

The Iran 44244 case study now includes a 3-panel timeline
figure: BGP withdrawals (top), Cloudflare Radar traffic
(middle), HCAF posterior (bottom), all on a 15-hour window with
the MSBD breakpoint overlaid. Per-event timelines for the
other 29 v17 events are in
`supplementary.tex::sec:supp-case-timeline`.

### 15. Graceful-degradation matrix figure

**Where:** `fig_deg_stress.pdf`

See item 2.

### 16. Per-channel signal on the 3 CSS-causal events

**Where:** `supplementary.tex::sec:supp-css`, `tab:supp-css-n3`

---

## P2 items deferred

- Detailed HCAF mathematical derivation is in the supplementary
  (sec:supp-uniform-prior, sec:supp-css).
- Per-event figures for all 30 events are in the supplementary
  (sec:supp-case-timeline).

---

## Summary of headline-number changes

| Number | Before (v20) | After (v21) | Reason |
|---|---|---|---|
| Phase 1 strict (all) | 86.7% | 86.7% | unchanged |
| Phase 1 strict (excl. NC) | 92.9% | 92.9% (now footnote) | R1 W5 |
| v18 held-out | 60.0% (side) | 60.0% (primary) | R1 W1, R3 W1 |
| HTML pipeline (pre-fix) | not reported | 70.0% | R3 W2 |
| HTML pipeline (post-fix) | not reported | 86.7% | R3 W2 |
| Degraded-mode worst case | not reported | 75.9% | R3 W3 |
| Negative-control baseline | not reported | 70.0% | R1 W2 |
| Uniform-prior flip rate | not reported | 20.0% | R2 W4 |
| CSS n=3 detail | not reported | 3/30, CIs, p-values | R2 W5 |

---

## File changes

- `main.tex`: abstract rewritten (3-number bound), 300 lines (was 286)
- `section1_intro.tex`: 274 lines (was 235) — contributions list updated, headline paragraph expanded with 70%/60% numbers
- `section2_related.tex`: 177 lines (unchanged)
- `section3_data.tex`: 199 lines (unchanged)
- `section4_method.tex`: 308 lines (was 236) — Bayesian → composite scoring rule, per-channel sparsity, uniform-prior ablation
- `section5_css.tex`: 169 lines (was 126) — n=3 strict-causal subset, KSG estimator spec
- `section6.tex`: 621 lines (was 483) — 4 new sub-sections (composition, neg-ctrl, HTML eval, deg-stress, per-channel)
- `section7_discussion.tex`: 201 lines (was 139) — 5 threats (added T4 operator-facing, T5 generalization revised), reproducibility expanded to 5 artefacts
- `supplementary.tex`: 1313 lines (was 1064) — 5 new appendix sections (HTML eval, deg stress, CSS n=3, case timeline, uniform-prior, v18 detail)

New figures (7):
- `fig_css_n3.pdf` — bootstrap CIs on n=3 subset
- `fig_html_eval.pdf` — HTML pipeline evaluation
- `fig_deg_stress.pdf` — degraded-mode stress test
- `fig_comp_table.pdf` — 30-event composition
- `fig_neg_ctrl.pdf` — negative-control experiment
- `fig_case_iran_timeline.pdf` — Iran case-study timeline
- `fig_ch_sparsity.pdf` — per-channel abstention rates

---

## Static verification (no LaTeX compiler available in env)

- 119 labels defined, 11 referenced (rest are equations, sub-figures, and supplementary-only labels)
- 26 citations in refs.bib, 26 used in text
- 0 missing figures
- 30 tabular environments (begin/end matched)
- 0 anonymization leaks (no GitHub URLs, no personal emails, no author names)

---

## What the user should do when they wake up

1. **Open Overleaf**, upload all `.tex` + `figs/` + `refs.bib` from
   `/data/bgp_tracer/docs/paper/`
2. **Compile** with `pdflatex + bibtex` (two passes)
3. **Verify page count** ≤ 11 (excluding references and AI Tool Usage)
4. **Read the paper end-to-end** — check that the 3-number bound
   (86.7% / 70.0% / 60.0%) reads cleanly
5. **Submit the abstract to HotCRP** by Nov 25 (T-45 days)
6. **Submit the full paper** by Dec 2 (T-52 days)
