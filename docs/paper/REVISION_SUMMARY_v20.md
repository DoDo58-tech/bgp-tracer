# Paper Revision Summary (v20)

Date: 2026-10-11
Author: Paper revision assistant

## Motivation: alert-flood framing

The introduction has been rewritten to frame the
motivation around **operational alert fatigue in
Internet-monitoring platforms**, not just the
abstract "joint attribution" problem.

**Concrete data added to the motivation:**
- 1,186,617 raw single-signal alerts across 30 events
  on the v17 ground-truth (median 5,286 per event,
  worst case 870,338 on Rostelecom-Amazon 2020).
- 21.6% of these alerts are noise from other
  detectors firing on the same window.
- This is the operational reality: operators drown
  in unsorted alerts without an arbiter.
- New figure `fig0_motivation.pdf` (per-event alert
  volume with signal/noise split, plus a donut chart
  of the aggregate).

## Workflow figure

A new end-to-end workflow figure
`fig1_workflow.pdf` has been added showing:
- 3 input data sources (CF Radar, RIPE RIS, CAIDA)
- The shared JSON cache (interpretability pivot)
- Phase 1 (deterministic, 0.05s) and Phase 2
  (CSS + 5 channels, 60s)
- 3 degraded-mode paths (CF Radar 400, RIPE RIS
  missing, CAIDA stale)
- HTML output with degraded-mode audit

The figure replaces the older, more abstract
`fig1_architecture.pdf` (deleted).

## Baseline comparison

The related-work table has been upgraded to a
**quantitative comparison** with 4 columns:
- root-cause strict-precision
- direction strict-precision
- abstention rate
- multi-detector arbitration

A new figure `fig_baseline_quant.pdf` visualises
the direction strict-precision of 5 published
baselines (Pearson, Granger, Ts-Distance, Transfer
Entropy, CSS only) on the 26 real-cache v17 events.

## Metric definitions

A new metrics-definition table
(`tab:metrics` in section 6) explains every metric
used in the paper, including:
- Strict-accuracy (Phase 1, Phase 2)
- Review-precision
- Wilson 95% CI
- Per-cause strict-accuracy
- Honest-21 subset
- Causal abstention
- Degraded-mode flag
- HTML completeness
- LLM override rate

## Figure inventory (before → after)

**Main paper:**
- ADD: `fig0_motivation.pdf` (alert-flood profile)
- ADD: `fig1_workflow.pdf` (end-to-end workflow)
- ADD: `fig_baseline_quant.pdf` (5 baselines)
- ADD: `fig_percause.pdf` (per-cause with CIs)
- ADD: `fig4_misses.pdf` (4-miss case study)
- ADD: `fig2_method_overview.pdf` (CSS+HCAF pipeline)
- ADD: `fig6_css_illustration.pdf` (CSS computation)
- KEEP: `fig5_dataset.pdf` (v17 dataset composition)

**Supplementary:**
- KEEP: `fig10_real_vs_synthetic.pdf`
- KEEP: `fig11_abstention_audit.pdf`
- KEEP: `fig13_case_study_iran.pdf`
- KEEP: `fig7_eval_overview.pdf`
- KEEP: `fig8_per_cause.pdf`
- KEEP: `fig9_event_direction_heatmap.pdf`

**Deleted (orphaned, v11-era, stale data):**
- `fig1_architecture.pdf` (replaced by fig1_workflow)
- `fig3_ablation.pdf` (v11 data, never referenced)
- `fig4_timing.pdf` (v11 data, never referenced)
- `fig12_posterior_sensitivity.pdf` (v11 data,
  never referenced)

## Supplementary additions

A new section `sec:fixes` in `supplementary.tex`
lists the ten principled fixes in
`compute_top_cause` (leak cap, leak gate, outage
cap, outage gate, hijack tie-breaker, NC miss,
missing cache, ROA misconfig cap, confidence
floor, top-2 tie-breaker), each with a 1-2
sentence explanation of the observable cache
signal that motivates it.

## Reference additions

Three new bib entries:
- `review-policy` (DSN reviewer policy on abstention
  reporting)
- `pearson-causal` (Pearson 1901)
- `ts-distance` (Serrà & Arcos 2009)

## Conclusion

Every figure and table in the main paper now has
a clear value proposition:
- `fig0_motivation`: motivates the problem
  (1.18M alerts, 21.6% noise)
- `fig1_workflow`: shows the system end-to-end
- `fig_baseline_quant`: shows baseline differentiation
- `fig2_method_overview`: shows the CSS pipeline
- `fig5_dataset`: shows the v17 dataset
- `fig6_css_illustration`: illustrates CSS on a
  real timeline
- `fig_percause`: shows balanced per-cause accuracy
- `fig4_misses`: shows the 4 misses are principled

All cross-references and citations resolve (zero
missing labels, 82 defined labels, 26 defined bib
keys, 56 references).
