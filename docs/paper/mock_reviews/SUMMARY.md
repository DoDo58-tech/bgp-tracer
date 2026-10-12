# Mock DSN Reviews — Summary

**Generated:** 2026-10-11 (Round-20 mock review, post-sensitivity)
**Target:** `docs/paper/main.tex` (post-Round-20 sensitivity, Oct 11 2026)
**Reviewers:** 3 (DSN-style skeptical, distinct perspectives)

---

## At-a-glance

| Reviewer | Perspective | Recommendation | Strongest concern |
|---|---|---|---|
| R1 (Systems / Dependability) | "Does the dependable-systems claim hold?" | **Major Revision** | v18 held-out 46.2% / 60.0% vs headline 86.7% gap (W1) |
| R2 (Causal-Inference Methodology) | "Is the Bayesian synthesis a valid causal-inference contribution?" | **Major Revision** | "Bayesian synthesis" is not a generative model (W1) |
| R3 (BGP Operational Realism) | "Would this help a NOC on a Tuesday morning?" | **Major Revision** | HTML pipeline is at 70.0%, not 86.7% (W2) |

All three reviewers recommend **Major Revision**. None recommend
**Reject**, because the reproducibility discipline and the
honest miss reporting are shared strengths across all three.

---

## Cross-cutting themes (recurring concerns)

### Theme A: The 86.7% headline is not the operator-facing number
- R1 W1: the v18 held-out 46.2% / 60.0% is operationally honest
- R3 W1, W2: the HTML pipeline is at 70.0%, not 86.7%
- **Consensus ask:** Promote the held-out and HTML-pipeline
  numbers to primary results.

### Theme B: The "principled fixes" framing is overstated
- R1 W2: ten fixes include at least three that are coupled to
  specific cases (factor of 5, `attack_signal_total` definition,
  0.05 boost tie-breaker).
- **Consensus ask:** Add a negative-control experiment (no fixes
  vs. all fixes) to bound the principled-fix contribution.

### Theme C: Bayesian synthesis is not a generative model
- R2 W1: the five channels are not independent; the LRs are
  heuristic; the posterior is not formally a posterior.
- R2 W4: the L1-ablation says the channels are redundant, but
  does not show that the synthesis-with-uniform-prior fails.
- **Consensus ask:** Either reframe as a scoring rule, or add a
  generative-model likelihood derivation.

### Theme D: Operator-facing evaluation is missing
- R3 W2: the HTML report (what the operator actually sees) is
  at 21/30 = 70.0%, with 6/30 regressions.
- R3 W3: the graceful-degradation claims are not stress-tested
  against the data failures we actually see (RIPE RIS lag,
  BGPStream rate-limit, Radar regional).
- R3 W4: the timing claim excludes the cache build.
- **Consensus ask:** Add the HTML-pipeline evaluation and the
  degraded-mode stress test.

---

## Actionable items (consolidated, by priority)

### P0 (must address before submission)
1. Add §6.x "HTML pipeline evaluation" with 21/30 = 70.0%,
   8/30 override, 6/30 regression, and post-fix number. (R3 W2)
2. Add §6.x "Degraded-mode stress test" with synthetic
   BGPStream rate-limit, RIPE RIS lag, Radar regional. (R3 W3)
3. Promote v18 held-out 60.0% to primary result. (R1 W1, R3 W1)
4. Add negative-control experiment for the 10 fixes. (R1 W2)
5. Reframe Bayesian synthesis as scoring rule OR add generative-
   model likelihood. (R2 W1)
6. Re-report timing including cache build. (R3 W4)

### P1 (should address)
7. Add "synthesis with uniform prior" ablation. (R2 W4)
8. Show bootstrap CIs on the n=3 CSS-causal subset. (R2 W5)
9. Specify TE estimator and report TE on n=3 subset. (R2 W6)
10. Add per-channel sparsity and per-channel commit analysis.
    (R2 W3)
11. Estimate "hijack + leak side-effect" rate on BGPStream.
    (R3 W5)
12. Add timeline figure to the Iran case study. (R3 W6)
13. Report 30-event composition by incident class, public
    source, year/quarter. (R1 W4)
14. Reorder headline to 86.7% as primary, 92.9% as footnote.
    (R1 W5)

### P2 (nice to have)
15. Show per-channel signal on the 3 CSS-causal events.
16. Add a "graceful-degradation matrix" figure (failure mode ×
    verdict accuracy).

---

## Per-reviewer detail

- [REVIEWER_1_SYSTEMS_DEPENDABILITY.md](./REVIEWER_1_SYSTEMS_DEPENDABILITY.md) — 5 weaknesses, 1 negative control ask
- [REVIEWER_2_CAUSAL_INFERENCE.md](./REVIEWER_2_CAUSAL_INFERENCE.md) — 6 weaknesses, 5 rebuttal questions
- [REVIEWER_3_BGP_OPERATIONAL.md](./REVIEWER_3_BGP_OPERATIONAL.md) — 6 weaknesses, 6 rebuttal questions
