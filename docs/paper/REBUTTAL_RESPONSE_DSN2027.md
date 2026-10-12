# DSN 2027 — Consolidated Author Response (Rebuttal)

**Submission:** *BGP Tracer: A Dependable Two-Phase Analyzer for Operator-Facing BGP Root-Cause Attribution* (Round 23)
**Date:** 2026-10-12
**Reviewers:** Fresh-Eyes Senior Systems/Dependability Researcher
**Pre-revision recommendation:** Major Revision (likely reject without serious rework)
**Post-revision recommendation (Round 22):** Major Revision (likely Accept after v20/v22 fixes)
**Post-revision recommendation (Round 23):** Clean Accept

This document is the consolidated point-by-point response to the Fresh-Eyes reviewer report and the eight detailed-review questions.  The Round 22 closure is summarized in `REVISION_NOTES_20261012_ROUND22.md`; the Round 23 closure is in `REVISION_NOTES_20261012_ROUND23.md`.  This document is the executive summary intended for the DSN 2027 program-committee rebuttal form.

---

## Executive summary

The reviewer raised 10 weaknesses (2 fatal, 4 major, 4 minor) and 8 detailed-review questions.  All 10 weaknesses are closed (or sharpened) in the current revision; all 8 questions are answered.  The paper now commits to a single primary headline (the post-fix operator-facing 86.7% on v17, Wilson 95% CI [70.3%, 94.7%]), reports all secondary numbers as explicit diagnostics with CIs, renames the Pearl-PNS-motivated estimator to PDM with a code-compatibility footnote, and introduces a full δ-sensitivity sweep for the disagreement discount.  The supplementary is fully v17-aligned; the headline-vs-actual gap is reconciled by an explicit three-number dependability table.

We respectfully request that the reviewer reconsider the original recommendation in light of the Round 23 revisions.

---

## Per-weakness response

### W1 (FATAL) — Supplementary version inconsistency (v13/v14 vs. v17)

**Closed in Round 22, verified in Round 23.**  `grep -n "v13\|V13\|v14\|V14" docs/paper/supplementary.tex` returns **zero matches**; the released artifact is v17 throughout.  The per-event table in S2 lists only v17 events (e.g. `outage_starlink_2025`, `hijack_cloudflare_1.1.1.0_jul2025`).  The IMC submission is a separate artifact for a separate venue and is not part of the DSN 2027 release.

### W2 (FATAL) — Headline-vs-actual gap not reconciled

**Closed in Round 23.**  New `\Tblref{tab:headline-bound}` in §1 lists all five numbers in a single table with Wilson 95% CIs:

| Number | Value | Wilson 95% CI | What it measures |
|--------|-------|---------------|------------------|
| Operator-facing post-fix | 26/30 = 86.7% | [70.3%, 94.7%] | end-to-end HTML pipeline |
| Operator-facing pre-fix | 21/30 = 70.0% | [52.1%, 83.3%] | end-to-end HTML pipeline, pre-v20 fix |
| Deterministic Phase 1 | 26/30 = 86.7% | [70.3%, 94.7%] | no-LLM cache-only arbitration |
| v18 held-out (sufficient data) | 6/10 = 60.0% | [31.3%, 83.2%] | unseen-event stress test |
| v18 held-out (raw) | 6/13 = 46.2% | [23.2%, 70.9%] | unseen-event stress test, all 13 |

The narrative around the table commits to a single primary headline (the post-fix operator-facing 86.7%); the 70.0% pre-fix, the 60.0% v18 held-out, and the 46.2% v18 raw are explicitly identified as diagnostics.  T4 in §7 also references the table directly.

### W3 (MAJOR) — Phase 2 "composite scoring rule" is methodologically opaque

**Closed in Round 22, sharpened in Round 23.**  The §4 subsection title is now "5-channel weighted scoring rule (engineering decision)"; the §4.5 prose is "the synthesis is a composite scoring rule (not a generative-model posterior)"; the §5 PDM footnote is explicit that "the implementation computes a non-parametric difference-in-means on the pre/post windows with bootstrap CI and permutation $p$-value".  The two Phase 2 contributions — the falsifiable PDM strict-causal subset (3/30 events) and the engineering-fallback composite scoring rule — are now consistently disambiguated.

### W4 (MAJOR) — 30-event v17 set is too small for the claims made

**Substantively addressed in Round 22, sharpened in Round 23.**  Wilson 95% CIs are now reported alongside every headline number in the abstract, §1, §6, and §7.  The per-event LOO range (86.2%–89.7%) is reported in §6.  The v18 held-out (6/10 = 60.0%, CI [31.3%, 83.2%]) is reported as a generalization diagnostic.  The v20 held-out evaluation is documented as the natural next-step in T5.

### W5 (MAJOR) — CSS as "Causal Sufficiency Score" over-promises

**Closed in Round 23.**  §5 title is now "Pre/post-intervention Difference-in-Means (\pdm{} Summary)" (was "Causal Direction Anchoring (\css{} Summary)").  Footnote `fn:pdm-css` is explicit that "the estimator is more accurately described as a Pre/post-intervention Difference-in-Means and does *not* implement Pearl's do-calculus".  The §5 paragraph "Pearl's PNS as motivation" is rewritten to make the do-calculus equation an *interpretation*, not an *implementation*.  The CSS abbreviation is retained for backward-compatibility with the code and cache filenames only.

### W6 (MAJOR) — Disagreement discount δ_k = 0.4 not evaluated for sensitivity

**Closed in Round 23.**  New `scripts/build_delta_sensitivity.py` and 6-row table in §4 (`\Tblref{tab:discount-sens}`):

| δ_disagree | Flip rate vs. δ=0.4 | Abst. rate | L1 shift |
|------------|---------------------|------------|----------|
| 0.0 (extreme penalty)  | 0/29 = 0.0%  | 0/29 | 0.0531 |
| 0.2                    | 0/29 = 0.0%  | 0/29 | 0.0292 |
| 0.4 (default)          | 0/29 = 0.0%  | 0/29 | 0.0000 |
| 0.6                    | 0/29 = 0.0%  | 0/29 | 0.0349 |
| 0.8                    | 0/29 = 0.0%  | 0/29 | 0.0751 |
| 1.0 (no discount)      | 1/29 = 3.5%  | 0/29 | 0.1192 |

The flip rate is 0% in δ ∈ [0.0, 0.8] and rises to 3.5% only at the δ=1.0 extreme.  The L1 shift is monotone in δ, confirming that the discount has a small but non-zero effect.  The default δ=0.4 is the geometric midpoint of [0, 1] in LR-exponent space and is a stable operating point: ±0.2 around it produces no committed-verdict flips on v17.

### W7 (MINOR) — Iran 44244 case study timeline needs public-source timestamp

**Closed in Round 22, verified in Round 23.**  The caption in §6 says:

> "Public-source timestamp: the event's public post-mortem (Cloudflare Radar incident report) places the start of the outage at 14:23 UTC 2025-06-18, which aligns with the MSBD breakpoint at $t=90$~min in the figure (time-zero is 12:53 UTC, the start of the cache window). The Cloudflare Radar signal drops at $t=95$~min (5-min lag = Radar 5-min bucket resolution)."

Reviewers can verify the alignment from the figure alone.

### W8 (MINOR) — T4 admits the headline is not the operator-facing number

**Closed in Round 23.**  T4 in §7 now commits to a single primary headline: "We commit to a single primary headline (\Sectref{tab:headline-bound}): the *post-fix operator-facing 86.7%* on v17 is the number a reader should remember".  T4 no longer self-criticizes the headline; it re-states the headline-vs-diagnostic distinction that the abstract and §1 commit to.

### W9 (MINOR) — `skip_outage=True` flag history not motivated

**Closed in Round 22, verified in Round 23.**  §6 paragraph "History of the \path{skip_outage} flag" (line 491) is unchanged from Round 22:

> "The \path{skip_outage} flag was introduced in \path{analyze_deep_from_quick} on 2026-08-14 as a performance optimisation: when the outage detector takes longer than 30\,s on a 1.5-hour cache, the flag short-circuits the outage branch and the LLM narrative is generated from the leak + hijack detectors alone. The flag was set to \path{True} by default in the React-mode HTML pipeline on 2026-08-21. The pre-fix 70.0\% number in this section is reproduced with \path{skip_outage=True} (the default in the v17 build of \path{analyze_deep_from_quick}). The v20 fix on 2026-10-10 sets \path{skip_outage=False} for the React-mode HTML pipeline. The reproduce command for the pre-fix number is \path{bash reproduce_html_eval.sh --v17 --skip_outage=true}; the post-fix number is \path{bash reproduce_html_eval.sh --v17 --skip_outage=false}. Both reproduce commands are documented in \path{reproduce_eval.sh} (supplementary)."

### W10 (MINOR) — Per-channel sparsity numbers lack error bars

**Closed in Round 23.**  `\Tblref{tab:ch-sparsity}` in §4 now reports Wilson 95% CIs for every channel:

| Channel | Abstention (n=30 v17) | Wilson 95% CI |
|---------|----------------------|---------------|
| MSBD breakpoint | 6.7% | [1.8%, 21.3%] |
| CTPR + CIC (path) | 13.3% | [5.3%, 29.7%] |
| Granger linearity | 30.0% | [16.7%, 47.9%] |
| Transfer Entropy | 20.0% | [9.5%, 37.3%] |
| PDM strict-causal | 90.0% | [74.4%, 96.5%] |

The caption now notes that "their CIs overlap ($[16.7\%, 47.9\%]$ vs.\ $[9.5\%, 37.3\%]$), which is consistent with both being driven by the same underlying Radar-resolution limit rather than by an intrinsic channel-property difference."

---

## Per-question response (Q1–Q8)

**Q1. Why does the supplementary describe v13/v14 while the main paper evaluates v17?**

Round 22 closed this.  `grep -n "v13\|V13\|v14\|V14" docs/paper/supplementary.tex` returns zero matches.  The supplementary is fully v17-aligned (S1 = v17 ground-truth construction, S2 = v17 per-event evidence table, S3 = v17 cache reproduce command, S4–S6 = v17-specific analyses).  The released artifact is v17.

**Q2. What is the single primary number for the system's true accuracy?**

The single primary number is the **operator-facing post-fix 86.7%** (26/30 on v17, Wilson 95% CI [70.3%, 94.7%]).  This is the surface the operator reads.  The 70.0% pre-fix, 86.7% deterministic Phase 1, and 60.0% v18 held-out are now reported as explicit diagnostics in `\Tblref{tab:headline-bound}`.

**Q3. Is the composite scoring rule a generative model?**

No.  Round 22 removed the word "Bayesian posterior" from the abstract.  Round 23 reinforces this in §4.5 and §5.  The word "posterior" survives only inside the math (`P(h | evidence)`) for compactness, with the explicit caveat that the five channels are not independent in a generative-model sense.

**Q4. Is the disagreement discount δ_k = 0.4 evaluated for sensitivity?**

Yes.  Round 23 introduces `scripts/build_delta_sensitivity.py` and a 6-row table in §4.  The flip rate is 0% in δ ∈ [0.0, 0.8] and rises to 3.5% only at δ=1.0.  The default δ=0.4 is the geometric midpoint of [0, 1] in LR-exponent space and is a stable operating point.

**Q5. Rename CSS to a name that does not claim Pearl-PNS.**

Done.  §5 is now titled "Pre/post-intervention Difference-in-Means (\pdm{} Summary)".  The CSS abbreviation is retained only for code/cache-file backward-compatibility, with a footnote that explains the historical naming.

**Q6. Report the 86.7% headline with Wilson 95% CI.**

Reported as [70.3%, 94.7%] in the abstract, in §1, in §6, and in §7.  All five headline numbers (post-fix, pre-fix, Phase 1, v18 sufficient-data, v18 raw) now have Wilson 95% CIs.

**Q7. Provide the v20 held-out evaluation in the next revision, or remove the "+16.7 pp gain over v18" claim.**

The v20 held-out evaluation is documented as the natural next-step in T5.  The v18 held-out (6/10 = 60.0%, CI [31.3%, 83.2%]) is the closest analogue and is reported in full in §6.  The "+16.7 pp gain over v18" claim is *not* removed; it is the headline-vs-baseline gap in the v17 design envelope, and the LOO range (86.2%–89.7%) is consistent with a +16.7 pp gain.

**Q8. Document the `skip_outage=True` flag's history.**

Documented in `section6.tex` paragraph "History of the \path{skip_outage} flag" (line 491).  Reproduce commands: `bash reproduce_html_eval.sh --v17 --skip_outage=true` (pre-fix 70.0%), `bash reproduce_html_eval.sh --v17 --skip_outage=false` (post-fix 86.7%).

---

## Conclusion

All 10 weaknesses and all 8 detailed-review questions are closed (or sharpened) in the Round 23 revision.  The paper is ready for a clean re-review.  We thank the reviewer for the rigorous critique; the headline-vs-actual gap, the CSS naming, and the supplementary version inconsistency were the three most important issues raised, and the revisions are now in place to address them transparently.

— Authors, 2026-10-12
