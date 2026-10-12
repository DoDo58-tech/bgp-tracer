# Reviewer Report on "BGP Tracer" (DSN 2027 submission)

**Reviewer persona:** Senior systems/dependability researcher, NOT
a BGP expert. Reads the paper as a generic applied-ML/systems
contribution. The reviewer is generous on engineering rigor but
harsh on methodological clarity, falsifiability, and the
"so what?" question.

**Review date:** 2026-10-12
**Manuscript version:** Round-21 (post-mock-review)

---

## TL;DR

**Recommendation: Major Revision (likely reject without serious rework).**

The paper has a real operational story (alert flood, multi-detector
arbitration, three dependability properties) and a serious
engineering artifact (deterministic Phase 1, 30-event v17
ground-truth, 86.7% strict). But the methodological framing of
the Phase 2 contribution is **not defensible as causal inference**
in its current form, the headline-vs-actual gap (86.7% deterministic
vs 60.0% held-out vs 70.0% HTML pipeline) is **not adequately
reconciled**, and the supplementary material **contradicts the
main paper's version numbering** (S1-S3 still describe v13/v14
while the main paper evaluates v17). The reproduction
discipline is genuine but the paper does not yet demonstrate
that the system generalizes beyond the curated set.

If the authors fix the Phase 2 framing, reconcile the
headline-vs-actual gap with a single primary number, scrub the
supplementary for version consistency, and demonstrate
behavior on a fresh held-out set in the next revision, this
could become acceptable. As written, it's a borderline reject.

---

## Strengths (the genuine ones)

1. **Operational motivation is real.** The 1.18M alerts / 21.6%
   noise framing (Section 1, Fig 0) is the kind of operational
   story DSN reviewers appreciate. This isn't a paper looking
   for a problem; the problem is real and quantified.

2. **The deterministic Phase 1 is auditable.** Reading
   `compute_top_cause` end-to-end and seeing the ten principled
   fixes is a much better story than "we trained a classifier
   on v17". The negative-control experiment (70 → 79.3 →
   86.7%) is the right move; this paper deserves credit for
   doing it.

3. **Reproducibility discipline is genuine.** Two-shell-command
   reproduction, audit trail of 169 rejected candidates, per-event
   cache files. The reproducibility section is short but real.

4. **The four-miss audit is honest.** Two detector-coverage
   limits, one upstream-API degradation, one NC definition
   quirk. The authors don't hide the misses.

---

## Weaknesses (in priority order)

### W1. (FATAL) The supplementary material contradicts the main paper's version numbering.

The main paper evaluates the **v17** ground-truth (30 events,
3 cause classes + 1 NC) and reports the v19 evaluation protocol.
The supplementary's S1 ("V13 Ground-Truth Dataset Construction
Report"), S2 ("V14 ... Differences vs V13"), and S3 ("Baseline
Evaluation Report (29-event v13/v14)") describe a **v13/v14
dataset with 29 events, 4 cause classes including
`roa_misconfig`, target composition 12+10+6+1**, which is a
different dataset entirely. The per-event table in
`supplementary.tex:170-180` lists `bgpstream_hijack_v13_*` events
that don't appear in the main paper's v17 evaluation.

A reviewer reading the main paper, then opening the
supplementary, will conclude that the authors either (a) didn't
update the supplementary when they moved to v17, or (b) the
reproducibility claim is hollow because the released artifact
is a different artifact. **Either interpretation is fatal to
the paper's credibility.** The supplementary must be
synchronized with the v17 evaluation.

### W2. (FATAL) The headline-vs-actual gap is not reconciled.

The abstract reports three numbers: 86.7% (deterministic Phase 1),
70.0% (HTML pipeline pre-fix, post-fix 86.7%), and 60.0% (v18
held-out). The 86.7% headline is the no-LLM, cache-only score on
the curated 30-event v17 set. The 60.0% held-out is on 10/13 v18
events with sufficient data. The 70.0% HTML pipeline is the
pre-fix operator-facing accuracy.

These three numbers tell **three different stories**:
- 86.7% = "the algorithm is good, in the regime where it was
  tuned"
- 70.0% = "the operator-facing surface is worse than the
  algorithm"
- 60.0% = "on unseen events, the algorithm is much worse"

A reviewer will ask: **"Which number is the system's true
accuracy?"** The paper's answer ("the dependability story is
the relationship between these three numbers") is rhetorical
hand-waving. If the headline were 70.0% (the operator-facing
number, with the v20 fix unverified on a fresh set), the
acceptance probability would be very different than if the
headline were 86.7%. The paper needs to commit to a single
primary number, justify why, and treat the other two as
secondary diagnostics.

### W3. (MAJOR) The Phase 2 "composite scoring rule" is methodologically opaque.

The Phase 2 design combines five evidence channels (MSBD, CTPR,
CIC, Granger, TE) under a "CSS-anchored prior" via a product of
likelihood ratios. The paper correctly admits the five channels
share routing-side evidence and are not independent in a
generative-model sense, and therefore reframes the synthesis as
a "scoring rule" rather than a Bayesian posterior. This is
honest, but it removes the only methodological justification
for the synthesis structure. The paper is now claiming:

> "We combine 5 channels' heuristic scores with a Pearl-PNS
> anchor, using a product of LRs, and we calibrate the
> prior weight to 10× via a uniform-prior ablation that shows
> 20% flip rate."

This is a **scoring rule**, not a causal-inference result. The
paper should commit to this framing: drop the "Bayesian" /
"posterior" language entirely, treat the synthesis as an
engineering decision (a 5-input weighted vote with a
heuristic-shaped prior), and stop claiming a falsifiable
significance result on Phase 2. **A Pearl-PNS-anchored
scoring rule is fine as engineering, but it is not a
causal-inference contribution** — and the current paper
muddles the two.

The CSS strict-causal n=3 subset is the only genuine
falsifiable causal claim. The paper should lean on this
3/30 rate as the methodological contribution and stop
over-selling the composite scoring rule.

### W4. (MAJOR) The 30-event v17 set is too small for the claims made.

The paper reports:
- 86.7% strict-accuracy (26/30, Wilson 95% CI ≈ [70%, 95%])
- Per-cause accuracy with single-event misses (e.g., 1/1 NC
  miss accounts for 50% of the "92.9% vs 86.7%" gap)
- LOO range of 86.2%-89.7%

The 30-event sample is so small that a single event changes
the headline by 3.3 percentage points. The 86.7% Wilson CI is
wide; the +16.7 pp gain over v18 baseline is in the
near-tail of the CI. **The paper's headline result is not
statistically distinguishable from a +5 pp improvement on a
noisy 30-event sample.** A reviewer will not be convinced that
the ten principled fixes are generalizable fixes rather than
artifacts of fitting to 30 specific events. The negative-control
experiment partially addresses this (70 → 79.3 → 86.7%
progression) but does not address the small-sample issue.

The paper should either (a) run a v20 held-out evaluation
(committed future work) to confirm the fixes generalize, or
(b) be more honest that n=30 supports a 75-90% accuracy claim
with substantial uncertainty, not a precise 86.7% claim.

### W5. (MAJOR) CSS as "Causal Sufficiency Score" over-promises.

The CSS engine computes the difference-in-means of pre/post
traffic around an MSBD-detected intervention, with bootstrap
CI and permutation p-value. This is **a before/after
difference-in-means test with intervention timing, not Pearl's
PNS**. Pearl's PNS is defined for binary X, Y, and requires
identifying the counterfactual distribution. The paper
acknowledges this in section 5.5 ("Pearl's PNS is defined for
binary X,Y but our BGP telemetry is a 0/1 binary series with
sparse bucket occupancy") but proceeds to call the score CSS
and to cite Pearl in the equation anyway.

The score is more accurately described as a "Lagged Difference
in Means" (LDM) or "Bootstrap Difference in Means" (BDM). The
Pearl-PNS framing is misleading because the estimator does not
implement do-calculus or counterfactual identification. **A
reviewer who knows causal inference will flag this immediately.**

This is not a fatal issue — the calculation is reasonable as
a non-parametric test for pre/post intervention effect — but
the paper should rename CSS to something honest and stop
claiming Pearl-PNS-anchoring.

### W6. (MAJOR) The composite scoring rule's claim of "no information without corroboration" is not evaluated.

Section 4.5 (Sec:bayesian) introduces a "disagreement discount"
δ_k ∈ {0.4, 1.0}: channels opposite the CSS-anchored direction
are down-weighted by 0.4, agreeing channels receive 1.0. The
claim is that this implements Pearl's "no information without
corroboration" principle. The paper does not evaluate the
sensitivity of the composite score to δ_k; the choice 0.4 is
not derived from any first-principles argument; the
"corroboration principle" is a metaphor, not a theorem.

The uniform-prior ablation (20.0% flip rate) tells us the
prior matters, but it does not tell us the disagreement
discount matters. A reviewer who notices this will ask: **what
if the disagreement discount is 0.0 (no penalty for
disagreement)?** If the answer is "same flip rate", the
discount is a free parameter and the paper's claim of
corroboration is rhetorical. If the answer is "much higher
flip rate", the claim is supported and the paper should
report the sensitivity sweep.

### W7. (MINOR) The Iran 44244 case study timeline figure shows a 15-hour window with a "MSBD breakpoint at t=90 min". 

The figure is well-constructed but the reader cannot tell from
the figure alone whether the 4 detector signals align with the
event's public start time. A timeline marker (e.g., "Event
public start time: 14:23 UTC, 2025-06-18") would help. The
current figure has the MSBD breakpoint but no public-source
timestamp.

### W8. (MINOR) The "Threat T4. Operator-facing gaps" subsection is a self-criticism that the paper's headline is not the operator-facing number.

T4 essentially admits that the 86.7% headline is the
cache-amortised deterministic number, not the operator's
realistic accuracy. This is an unusual move — most papers put
the operator-facing number in the headline. The fact that T4
exists in the discussion section means a reviewer reading the
threats will conclude the headline is misleading.

### W9. (MINOR) The pre-fix HTML pipeline evaluation depends on a `skip_outage=True` flag that is not motivated anywhere.

The paper reports that 6/30 v17 events are LLM regressions
because `skip_outage=True` makes the LLM see "5000 leak events
+ Outage Skipped" and conclude "Route Leak". But the paper
never explains why `skip_outage=True` was set in the first
place, or why the post-fix is `skip_outage=False` (a one-line
change). A reviewer who tries to reproduce the 70% pre-fix
number will not know which `skip_outage` value was used in
which version of the code. The audit trail is incomplete.

### W10. (MINOR) The per-channel sparsity numbers (6.7%, 13.3%, 30.0%, 20.0%, 90.0%) are presented without error bars.

A 30-event sample with 1 event granularity means a 3.3%
sparsity change. The per-channel sparsity table does not
report CIs. The 30% Granger vs 20% TE difference is well
within the n=30 noise.

---

## Detailed review questions for rebuttal

1. Why does the supplementary describe v13/v14 while the main
   paper evaluates v17? Is the released artifact v17 or v13?
2. What is the single primary number for the system's true
   accuracy? Justify why.
3. Is the composite scoring rule a generative model? If not,
   why is the term "posterior" used in the abstract?
4. Is the disagreement discount δ_k = 0.4 evaluated for
   sensitivity? Report the flip rate at δ_k = 0.0, 0.2, 0.4,
   0.6, 0.8, 1.0.
5. Rename CSS to a name that does not claim Pearl-PNS if
   the estimator does not implement do-calculus.
6. Report the 86.7% headline with Wilson 95% CI: the
   current presentation makes a point estimate of 86.7% look
   precise; the CI is [70%, 95%].
7. Provide the v20 held-out evaluation in the next
   revision, or remove the "+16.7 pp gain over v18" claim.
8. Document the `skip_outage=True` flag's history: when was
   it introduced, when removed, and what was the reproduce
   command for the pre-fix 70% number?

---

## Recommendation

**Major Revision.** The operational story, the deterministic
Phase 1, the negative-control experiment, and the
reproducibility discipline are genuine strengths. The
headline-vs-actual gap, the supplementary version
inconsistency, and the Phase 2 methodological framing are
genuine weaknesses that cannot be papered over with rhetoric.

If the authors:
- Reconcile the supplementary with v17 (or remove the v13/v14
  sections entirely)
- Commit to a single primary number (recommendation: 70.0%
  HTML pipeline post-fix, with 86.7% deterministic and 60.0%
  v18 held-out as supporting diagnostics)
- Reframe Phase 2 as a "5-channel composite scoring rule"
  with explicit "engineering" rather than "causal inference"
  language
- Rename CSS to a non-Pearl-claiming name
- Add a v20 held-out evaluation

— then this becomes a clean accept.

As written, the paper has too many version inconsistencies and
methodological over-claims to be a DSN accept.

---

## Score (out of 5, DSN scale)

- Originality: 3.5/5 (operational story is fresh; engineering
  is solid; methodology is over-claimed)
- Technical soundness: 2.5/5 (Phase 1 is sound; Phase 2
  framing is not; supplementary is out of sync)
- Clarity: 3.0/5 (well-organized; 3-number bound muddles the
  story)
- Reproducibility: 4.0/5 (the discipline is real; the
  supplementary contradicts the main paper)
- Significance: 3.0/5 (operator-relevant; the 60% held-out
  caps the impact)

**Overall: 3.0/5 → Major Revision (likely reject without
serious rework).**
