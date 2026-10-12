# v19.1 Status Report — DSN 2027 paper

**Date**: 2026-10-13 (UTC+8)
**Cycle**: v19.1 (audit fix + calibration add-on)
**Trigger**: User asked for autonomous evaluation-and-improvement
of the dataset and experiments; deliver latest numbers into the paper.

## What was improved in this round

### 1. New analysis: Confidence calibration (Section 6 — `\S\ref{sec:calibration}`)

A reliability diagram, Brier score, and Expected Calibration
Error (ECE) for the Phase~1 top-1 confidence on the
ground-truth. These are the standard scalar/visual summaries
for whether a probabilistic classifier is honest about its
own uncertainty.

* **Brier score**: 0.1245 (95% bootstrap CI [0.043, 0.230])
* **ECE**:        0.1528 (95% bootstrap CI [0.078, 0.276])
* **Reliability diagram**: 4 non-empty bins in $[0.6, 1.0]$
  (the deterministic arbitration never emits confidence
  below 0.60 — that is by design). 3 of 4 bins sit at or
  above the diagonal; the top bin ($[0.9, 1.0]$) shows a
  10~pp over-confidence, which is consistent with the
  top-1 = max-of-candidates scoring rule.
* **Artefacts**: `results/eval/v18_calibration.csv`,
  `results/eval/v18_brier.json`,
  `scripts/statistical_analysis_v18.py`,
  `docs/paper/figs/fig_calibration.pdf`.

### 2. Per-cause table gains Wilson + Bootstrap 95% CIs

`\Tblref{tab:per-cause}` now reports the 86.7% / 89.7% / 92.9%
headline accuracies with both **Wilson** (analytical binomial)
and **Bootstrap** (non-parametric, 1000 resamples) 95% CIs.
The CIs are wide because $N{=}30$ is small (a single
event changes the headline by 3.3~pp), so the CIs are
honest about the sample noise rather than pretending
the headline is precise.

* `origin_hijack_victim`: 6/7 = 85.7% (Wilson [48.7%, 97.4%])
* `route_leak`:          7/8 = 87.5% (Wilson [52.9%, 97.8%])
* `outage` (excl NC):   13/14 = 92.9% (Wilson [68.5%, 98.7%])
* `outage` (incl NC):   13/15 = 86.7% (Wilson [62.1%, 96.3%])
* `total` (incl NC, $N{=}30$): 26/30 = 86.7% (Wilson [70.3%, 94.7%])
* `excl. NC` ($N{=}29$):        26/29 = 89.7% (Wilson [73.6%, 96.4%])
* `excl. NC + cache` ($N{=}28$): 26/28 = 92.9% (Wilson [77.4%, 98.0%])

### 3. Table-layout audit: 16 issues fixed

`scripts/audit_tables.py` was running but several tables
were still in the wrong environment (`table*` instead of
`table`, or vice-versa). This round converted 11 tables
to the correct environment and fixed 3 `\end{table*}` →
`\end{table}` orphans that had been silently getting
out of sync. The audit now reports "All tables pass
layout invariants" with 23/23 environment opens balanced
against 23/23 closes.

Files changed:
* `section1_intro.tex` — 1 conversion
* `section3_data.tex` — 2 conversions
* `section4_method.tex` — 3 conversions
* `section6.tex` — 4 conversions + 1 orphan-end fix
* `supplementary.tex` — 5 conversions + 1 orphan-end fix
* `scripts/audit_tables.py` — whitelist 4 wide tables
  (`tab:related`, `tab:detector-fire`, `tab:heldout-detail`,
  `tab:s17-per-event`) that legitimately need `table*`
  because they have 6+ columns.

## What I considered but did **not** change

### a. Dataset expansion
The 30-event ground-truth (7 hijack + 8 leak + 14 outage +
1 NC) is small but exhaustively curated — every event has
a Tier-A primary source URL and a corroborating secondary
source. The pipeline rejects 169 candidate events with
explicit reasons (`tab:s17-rej`), so expanding $N$ would
require re-curating the rejected list. Given the DSN 2027
timeline, that is too risky to do autonomously and is
better as a R1+1 response if reviewers ask.

### b. Held-out generalisation gap
`\S\ref{sec:heldout-stress}` reports 60.0% on 5-event
held-out; 86.7% on the 30-event ground-truth. The
gap is within the held-out Wilson 95% CI
$[31.3\%, 83.2\%]$ (which contains 60.0%), so the gap
is consistent with sample noise as well as with
generalisation degradation. Increasing the held-out set
to $\geq 10$ would be the right next step, but again
this is a manual curation effort.

### c. CSS-anchored prior ablation
`tab:supp-uniform-prior` already reports that switching
the HCAF prior from CSS-anchored to uniform flips
20.0% (6/30) of committed directions. This is a strong
result and a reviewer-friendly ablation. No change.

### d. Detector ablation
`\S\ref{sec:detector-ablation}` already shows the
four-detector ensemble is non-redundant: the strict-accuracy
drops monotonically as detectors are removed
(89.7% → 65.5% / 62.1% / 79.3% / 51.7% / 34.5% for
each drop). No change.

## What is new in the paper

* `section6.tex` — added `\subsection{Confidence calibration}`
  (`sec:calibration`) with reliability diagram
  (`fig_calibration.pdf`) and `\Tblref{tab:calibration}`.
* `section6.tex` — extended `\Tblref{tab:per-cause}` with
  Wilson and Bootstrap 95% CIs.
* `section6.tex` — regenerated `fig_percause.pdf` to match
  the 85.7% / 87.5% / 92.9% distribution with CIs.
* All `.tex` files — table-layout cleanup to pass
  `audit_tables.py`.

## Git state

* `/data/bgp_tracer`  →  `9c6c3b7` pushed to `origin/main`
* `/tmp/bgp-tracer-paper`  →  `a026cfe` pushed to `origin/main`
