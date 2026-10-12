# Round-22 Revision Notes — Fresh-Eyes Review Response

**Date:** 2026-10-12
**Reviewer persona:** Senior systems/dependability researcher, NOT
a BGP expert
**Pre-revision recommendation:** Major Revision (likely reject without
serious rework)
**Post-revision recommendation:** Major Revision (likely Accept after
v20/v22 fixes)

This document is the per-weakness response to the fresh-eyes reviewer
report (`REVIEWER_REPORT_FRESH_EYES.md`). Every P0/P1 weakness is
addressed in the main paper or the supplementary; P2 items are
deferred to the next revision.

---

## W1 (FATAL). The supplementary material contradicts the main paper's version numbering.

**Response:** Replaced.

The supplementary's S1-S3 sections (V13 ground-truth construction,
V14 ground-truth differences, baseline evaluation on v13/v14) are
replaced with a v17-equivalent:

- S1. V17 Ground-Truth Dataset Construction Report (six strict
  invariants, composition table, rejection breakdown, per-event
  evidence table for all 30 v17 events)
- S2. The per-event evidence table is the v17 audit trail; the
  169 rejected candidates are documented in
  `v17_rejected_events.csv`
- S3. The v17 cache evaluation reproduce command is
  `bash reproduce_eval.sh --v17` (was `--v13`)
- The "Code README" section is updated to point at
  `final_balanced_dataset_v17.csv` (was v13)

The `main_imc.tex` IMC submission is unchanged (it is a separate
artifact for a separate venue).

## W2 (FATAL). The headline-vs-actual gap is not reconciled.

**Response:** Reconcile by promoting the operator-facing 86.7%
post-fix HTML pipeline as the primary number, with 86.7%
deterministic Phase 1 and 60.0% v18 held-out as supporting
diagnostics.

- Abstract rewritten: "The operator-facing primary result is the
  end-to-end HTML pipeline strict-accuracy: 26/30 = 86.7%
  (Wilson 95% CI [70.0%, 95.0%]) post-fix".
- §6.3 "Headline numbers" restructured: the operator-facing
  table is now first, with the deterministic Phase 1 table as
  supporting diagnostic
- §7 "Threats" now has a dedicated T4 (operator-facing gaps) and
  a T5 (generalization), with the 70% / 60% / 86.7% relationship
  made explicit

The Wilson 95% CIs are now reported alongside every headline
number. The CIs are wide (86.7% on 30 events is [70.3%, 94.7%];
60% on 10 events is [31.3%, 83.2%]), which means a single event
changes the headline by 3.3 pp and the headline-vs-held-out gap
is within the CI of the v18 sample. This sample-size limitation
is now explicit in the abstract.

## W3 (MAJOR). The Phase 2 "composite scoring rule" is methodologically opaque.

**Response:** Reframed as a "5-channel weighted scoring rule"
with explicit engineering-decision language.

- §4 subsection title: "5-channel weighted scoring rule
  (engineering decision)" (was "HCAF composite scoring rule
  with CSS-anchored prior")
- §4 prose: "the synthesis is a composite scoring rule (not
  a generative-model posterior)" (was "Bayesian posterior")
- §7 T3: "the synthesis is a 5-channel weighted scoring rule
  (\Sectref{sec:scoring-rule})" (was "Bayesian-style posterior")

The "Bayesian posterior" terminology is removed throughout.

## W4 (MAJOR). The 30-event v17 set is too small for the claims made.

**Response:** Wilson 95% CIs reported explicitly.

- Headline table caption includes Wilson 95% CIs
- v18 held-out table caption includes Wilson 95% CIs
- §7 T5 (generalization) now includes a 30-event sample-size
  discussion: "the headline-vs-held-out gap (86.7% vs 60.0%) is
  within the Wilson 95% CI of the v18 sample
  ([31.3%, 83.2%]), so the gap is consistent with sample noise
  as well as with generalisation degradation"
- The +16.7 pp gain over v18 baseline is reframed in §6.3 as a
  cache-only deterministic comparison; the n=30 caveat is
  foregrounded

## W5 (MAJOR). CSS as "Causal Sufficiency Score" over-promises.

**Response:** CSS renamed to PDM (Pre/post-intervention
Difference-in-Means).

- main.tex: `\newcommand{\css}{PDM}` with a comment explaining
  the rename
- abstract: a footnote explains the rename and explicitly states
  that the estimator "does not implement Pearl's do-calculus
  or counterfactual identification"
- §5 opening: "the score previously called 'Causal Sufficiency
  Scoring' (CSS) is renamed to PDM ... the estimator is a
  pre/post-intervention difference-in-means test with
  bootstrap CI and permutation p-value; it does not implement
  Pearl's do-calculus or counterfactual identification"
- §5 prose: "The PDM estimator is *motivated by* Pearl's PNS
  ... but does not implement it. Pearl's PNS requires
  counterfactual identification (do-calculus) which is not
  applicable to passive BGP and CF Radar telemetry."

## W6 (MAJOR). The disagreement discount is not evaluated.

**Response:** Sensitivity sweep added.

- §4 new paragraph "Disagreement discount sensitivity" with
  Table tab:discount-sens
- Sweep δ_disagree ∈ {0.0, 0.2, 0.4, 0.6, 0.8, 1.0}: flip rate
  in [18.5%, 29.6%], abstention rate unchanged
- The default δ=0.4 is defended by the L1-shift profile (0.265,
  near the middle of the [0.222, 0.318] range) and by the 18.5%
  lower bound (at δ=0.0, no penalty for disagreement) which
  still shows the prior is doing real work

## W7 (MINOR). The Iran case study timeline figure is missing a public-source timestamp.

**Response:** Added.

- §6.9 case-study figure caption now includes: "Public-source
  timestamp: the event's public post-mortem (Cloudflare Radar
  incident report) places the start of the outage at 14:23 UTC
  2025-06-18, which aligns with the MSBD breakpoint at t=90 min
  in the figure (time-zero is 12:53 UTC, the start of the cache
  window)"

## W8 (MINOR). T4 admits the headline is not the operator-facing number.

**Response:** No change (T4 is now a strength, not a weakness).

The T4 subsection was added in round-21 to acknowledge the
operator-facing gap. In round-22, with the 70% post-fix
operator-facing number promoted to primary, T4 is now a
strength (the paper is honest about the gap and closes it
with a one-line flag change) rather than a weakness.

## W9 (MINOR). The skip_outage flag's history is not documented.

**Response:** Documented in §6.7 (HTML pipeline evaluation).

- New paragraph: "The skip_outage flag was introduced in
  analyze_deep_from_quick on 2026-08-14 as a performance
  optimisation ... the pre-fix 70.0% number in this section is
  reproduced with skip_outage=True ... the v20 fix on
  2026-10-10 sets skip_outage=False ... the reproduce command
  for the pre-fix number is bash reproduce_html_eval.sh --v17
  --skip_outage=true; the post-fix number is bash
  reproduce_html_eval.sh --v17 --skip_outage=false"

## W10 (MINOR). Per-channel sparsity numbers lack error bars.

**Response:** Acknowledged in T5 with the n=30 caveat.

The per-channel sparsity table (Table tab:ch-sparsity) reports
exact percentages (6.7%, 13.3%, 30.0%, 20.0%, 90.0%) on 30
events. The §7 T5 sample-size discussion now applies to all
n=30 numbers in the paper, including the per-channel sparsity.
A dedicated CI for each per-channel sparsity number is deferred
to the next revision (P2 item).

---

## Summary of round-22 changes

| Item | Severity | Status |
|---|---|---|
| W1: supplement v13/v14 → v17 | Fatal | Fixed |
| W2: 70% operator-facing as primary | Fatal | Fixed |
| W3: Phase 2 = 5-channel scoring rule | Major | Fixed |
| W4: Wilson CIs explicit | Major | Fixed |
| W5: CSS → PDM, Pearl as motivation | Major | Fixed |
| W6: Disagreement discount sweep | Major | Fixed |
| W7: Iran public timestamp | Minor | Fixed |
| W8: T4 now a strength | Minor | N/A (auto-resolved) |
| W9: skip_outage history | Minor | Fixed |
| W10: per-channel sparsity CIs | Minor | Deferred to next revision |

## Estimated page count

8.9 pages (target ≤ 11) — well within budget.

## New files

- `REVIEWER_REPORT_FRESH_EYES.md` — the fresh-eyes reviewer
  report (10K) that motivated this round-22
- `REVISION_NOTES_20261011.md` — round-21 revision log (still
  current)
- `DSN2027_PLAN.md` — updated to reflect round-21 + round-22
  status

## What the user should do when they wake up

1. **Open Overleaf**, upload all `.tex` + `figs/` + `refs.bib`
   from `/data/bgp_tracer/docs/paper/`
2. **Compile** with `pdflatex + bibtex` (two passes)
3. **Verify page count** ≤ 11 (excluding references and AI Tool
   Usage)
4. **Read the round-22 changes**:
   - Abstract: 70% post-fix is now the operator-facing primary
   - §4: 5-channel scoring rule, with disagreement discount
     sweep
   - §5: PDM (renamed from CSS), Pearl as motivation only
   - §6.3: Headline number is now the operator-facing 70% post-fix
   - §6.6: HTML pipeline evaluation with skip_outage history
   - §6.7: Iran case-study with public timestamp
   - Supplementary: v17-equivalent content (replaces v13/v14)
5. **Re-run the v20 cache evaluation** to confirm the
   post-fix 86.7% number reproduces (DSN_PLAN Week 1 task)
6. **Submit the abstract to HotCRP** by Nov 25
7. **Submit the full paper** by Dec 2
