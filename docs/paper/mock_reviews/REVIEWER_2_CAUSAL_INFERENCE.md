# Mock DSN Reviewer 2 — Causal-Inference Methodology Perspective

**Reviewer persona:** Prof. B. — causal-inference researcher;
familiar with Pearl's do-calculus, time-series causal discovery
(Granger, PCMCI, TE), and the pitfalls of post-hoc causal
modelling; skeptical of "Bayesian synthesis" claims that are
not backed by a clear generative model.
**Review target:** `docs/paper/main.tex` (post-Round-20 sensitivity, Oct 11 2026)

---

## Summary

The paper proposes a Phase 2 hierarchical causal arbitration
framework (HCAF) that combines five evidence channels (MSBD,
CTPR+CIC, Pearson, Granger, TE) under a Bayesian posterior with
a CSS-anchored prior. The causal claim is that HCAF commits a
direction (R→T, T→R, independent, or abstain) per event. I find
the framework conceptually interesting but the methodology has
several gaps that prevent it from being evaluated as a causal-
inference contribution. I recommend **Major Revision**.

---

## Strengths

1. **CSS engine design is principled.** The CSS engine uses
   Pearl-PNS (Probabilistic Neighborhood Selection) on the
   difference-in-means of routing and traffic time series, with
   bootstrap CIs. This is a reasonable test for the null of
   "no causal direction" in the linear case. Section 5 is well-
   written.

2. **The CSS-anchored prior is a non-trivial design choice.**
   Rather than uniform priors, the HCAF prior puts weight 10 on
   the CSS direction (if causal) or 4 (if not causal) and
   weight 1 on the other three hypotheses. This encodes the
   design choice that "the data, not the prior, decides", and
   the prior magnitudes (10 vs 1) are a 10:1 odds ratio that
   is recoverable from the paper.

3. **The honest reporting of CSS strict-causal rate ≤ 3/30 is
   methodologically correct.** Most BGP-monitoring papers that
   invoke causality never report how often their test rejects
   the null. The 3/30 number is small, but the paper is
   transparent about it.

---

## Weaknesses

### W1. **The "Bayesian synthesis" is not a generative model.**

The HCAF posterior is defined by
$$P_0(h) \propto \begin{cases} 10 & h = \text{CSS.direction and CSS.is\_causal} \\ 4 & h = \text{CSS.direction and not CSS.is\_causal} \\ 1 & \text{otherwise} \end{cases}$$
and the five evidence channels contribute likelihood ratios
(LRs). But:

- The five channels are not independent, and the paper does
  not state a covariance model. The LRs are multiplied under
  an implicit independence assumption.
- The five LRs are computed from quantities with different
  units (MSBD: anomaly count; CTPR+CIC: path-integrity score;
  Pearson: correlation coefficient; Granger: F-statistic; TE:
  bits). The mapping from each quantity to its LR is not
  derived from a likelihood; it appears to be heuristic.
- The L1 posterior shift reported in §6.5 is the
  Kullback-Leibler divergence between the prior and posterior.
  This requires a probability distribution; the heuristic LRs
  do not produce a valid posterior.

**Concrete ask:** Either (a) define the five channels as
likelihoods of a stated generative model (e.g., "the routing
sequence X_t is drawn from a Gaussian AR(1) process with
parameters depending on the cause hypothesis"), or (b) rename
the synthesis as a **scoring rule** rather than a Bayesian
posterior. The current naming is methodologically misleading.

### W2. **Pearl-PNS is used, but the do-calculus is not.**

The CSS engine invokes Pearl-PNS, which is a constraint-based
causal-discovery algorithm (Spirtes-Glymour style). The
"causal direction" output is not the same as a Pearl-style
do-calculus intervention. The paper does not use do-calculus
or any intervention-style argument; it uses observational
lag-correlation (Pearson, Granger) and information-theoretic
(TE) measures.

This is fine, but the paper should not invoke Pearl in the
naming if it is not using Pearl's framework. **Concrete ask:**
Rename "CSS (Causal Sufficiency Score)" to "LDS (Lagged
Dependency Score)" or "LDD (Lagged Direction Discrimination)",
which is more honest about the actual computation.

### W3. **The 5-minute bucket resolution limit is structural, but
not all channels suffer equally.**

The paper reports that the CSS engine "fails to commit a
direction" on 27/30 events due to the 5-minute Radar bucket
limit. But the routing channel (BGP update timestamps) has
second-level resolution, not 5-minute. The paper does not
report the per-channel sparsity; only the CSS strict-causal
rate is reported.

**Concrete ask:** Report the per-channel sparsity
("fraction of v17 events where this channel returned a
non-degenerate signal"). The reader should be able to see
that CSS sparsity is a property of the *traffic* channel,
not the routing channel, and the HCAF's reliance on
routing-side evidence (CTPR, CIC) is a feature, not a
limitation.

### W4. **The L1 posterior shift "in [0.255, 0.291] when
removing a channel" is the wrong control.**

The paper reports that removing any one of the five channels
yields L1 shift in [0.255, 0.291] and 0% flip rate. This is
the expected shape if the five channels are **redundant**
in their posterior information. The paper interprets this
as "the prior is doing the work", but the ablation is
designed to show that the prior is *important* (it is) not
that the channels are *redundant* (the L1 says they are).

A more informative ablation would be: **how often does the
synthesis commit a direction** (i.e., reject `unknown`/
`abstain`) on a per-channel basis? If the synthesis only
commits when the CSS-anchored prior is non-uniform, then
the channels are doing nothing.

**Concrete ask:** Add a "synthesis with uniform prior" run.
Report the flip rate and abstention rate. If the flip rate
is 0% and the abstention rate is unchanged, the channels
are doing no work. If the flip rate is >10%, the channels
are doing real work; the current ablation does not show
this.

### W5. **The bootstrap CI on the PNS estimate is not
visualized.**

The paper reports that "CSS uses bootstrap CI to give PNS
a confidence interval; CI not crossing 0 is taken as
evidence of causality". But the bootstrap CI itself is not
shown anywhere in the paper or supplementary. A reader
cannot evaluate the claim without seeing the CIs.

**Concrete ask:** Show a single figure with the PNS point
estimate and 95% bootstrap CI for the 3 events where CSS
commits a direction (the n=3 subset). This is the strongest
empirical evidence the paper has for the CSS engine and it
should be in the main paper, not the supplementary.

### W6. **Transfer Entropy is non-parametric, but the
estimator is not specified.**

The paper uses TE as a "non-linear" causal channel. The
TE estimator (Kraskov-Stögbauer-Grassberger? discrete
binning? k-NN with k=4?) is not specified. The TE
estimator's bias is well-known to depend on the bin
count, the estimator family, and the sample size. A 5-min
bucket × 2-hour window = 24 samples, which is below the
KSG estimator's recommended minimum (typically 50+).

**Concrete ask:** Specify the TE estimator and the
recommended sample size. Report the TE values on the 3
events where CSS commits, with bootstrap CIs.

---

## Recommendation

**Major Revision.** The CSS engine design (Section 5) and the
ablation discipline (Section 6.5) are commendable, but the
Bayesian-synthesis framing (Section 4) overstates the
methodological rigor. I would accept a version that (a)
replaces the Bayesian framing with a scoring-rule framing,
(b) adds the per-channel sparsity and per-channel commit
analysis (W3, W4), and (c) shows the bootstrap CIs on the
3 events where CSS commits (W5).

---

## Questions for the rebuttal

1. Can you replace the Bayesian framing with a scoring-rule
   framing in the revised manuscript?
2. Can you show the per-channel sparsity and per-channel
   commit analysis?
3. Can you add the "synthesis with uniform prior" run?
4. Can you show the bootstrap CI figure on the n=3 CSS-
   causal subset?
5. Can you specify the TE estimator and report the TE
   values on the n=3 subset?
