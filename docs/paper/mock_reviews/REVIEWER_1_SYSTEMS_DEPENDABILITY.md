# Mock DSN Reviewer 1 — Systems / Dependability Perspective

**Reviewer persona:** Prof. A. — dependable systems researcher; familiar
with fault-tolerance and graceful-degradation literature; skeptical of
benchmark numbers that are not traceable to operational failure modes.
**Review target:** `docs/paper/main.tex` (post-Round-20 sensitivity, Oct 11 2026)

---

## Summary

The paper proposes a two-phase BGP-anomaly arbitration system with a
deterministic Phase 1 (86.7% strict on a 30-event ground-truth) and an
LLM-driven Phase 2 (HCAF Bayesian synthesis over five evidence
channels). The headline 86.7% and the v18 held-out 46.2% / 60.0%
numbers are the paper's central claims. I find the contribution
genuine but the dependability framing overstated. I recommend
**Major Revision**.

---

## Strengths

1. **Operational framing is honest.** Section 1 quantifies the
   alert-flood problem on real data (1.18M raw alerts on 30 events,
   21.6% noise rate) before introducing the system. This is rare in
   the BGP-monitoring literature and a credible motivation.

2. **Reproducibility discipline.** The two-shell-command
   reproducibility claim (§3) and the deterministic-only Phase 1
   evaluation (no LLM) are strong design choices. The cache files
   are auditable; the thresholds are observable; the fixes are
   enumerated. This is what "dependable" should look like.

3. **Graceful-degradation language is principled.** Table 4 (the
   4-miss audit) and the v18 held-out stress test (60.0% on
   sufficient-data events) are both reported honestly. I appreciate
   that the paper does not hide the misses.

4. **Ablation study is well-structured.** Detector ablation
   (Table 3) and LOO event analysis (Fig 7 right) are standard but
   done correctly; the per-cause fire-rate (Table 4) is informative.

---

## Weaknesses

### W1. **The "dependable" claim is not borne out by the v18 held-out result.**

The headline is 26/30 = 86.7% on v17, and the v18 held-out is
6/13 = 46.2% (or 6/10 = 60.0% excluding data-insufficient events).
The paper explains the gap as "light_mode pollution" in the v18
caches, but the framing is unsatisfying for a dependability venue:

- "Light_mode pollution" is a pipeline-internal artifact, not an
  operational failure mode. An operator receiving a v18 verdict has
  no way to know whether the system is in "light_mode" or
  "full_mode".
- The 60.0% on "sufficient data" still means 4/10 events get the
  wrong verdict. The paper should be explicit about what
  classification confidence is calibrated to when the outage
  detector is silent.
- **Concrete ask:** Define a "degraded-mode" flag in the cache (the
  paper already has a `degraded_mode` field per the metrics table)
  and report strict-accuracy conditioned on
  `degraded_mode == False`. This is the number an operator would
  actually use.

### W2. **The "ten principled fixes" (Section 5.x) read as
after-the-fact tuning.**

The paper claims each fix is a direct consequence of an observable
cache signal, not a tuning exercise. But several of the ten fixes
are coupled:

- Fix 5.4 raises the BUG-R140 cap threshold from 500 to 5000 when
  `origin_hijacking_n >= 5 * origin_hijacked_n`. The factor of 5
  is not derived from any first-principles argument; it is the
  smallest integer that prevents the 16509 2025-08-10 outage from
  being misattributed.
- Fix 5.7 introduces a new `leak_dominance_vs_attack` ratio
  specifically because the legacy `leak_dominance_ratio` "didn't
  fire" on Cloudflare 1.1.1.0. The new ratio uses
  `attack_signal_total` (excluded origin_hijacking) which is the
  only ratio that yields 66.7 on that case.
- Fix 5.8 adds a 0.05 boost to the leak verdict in a specific
  four-way conjunction. This is the textbook shape of an
  ad-hoc rule.

A reviewer can verify (as the paper claims) that none of these
reads a ground-truth label, but the **principle** of "observable
signal → principled fix" is harder to defend when the fixes are
sized to make specific cases stop misfiring.

**Concrete ask:** Add a **negative control**: report the strict-
accuracy on the v17 caches with the 10 fixes **replaced by a
single global threshold** (e.g., "pick the detector with the
highest count"). If this is below 70%, the fixes are doing real
work. If it is already at 80%, the principled-fix framing is
overstated.

### W3. **CSS strict-causal rate ≤ 3/30 is acknowledged as
"structural" but not defended.**

The paper reports that CSS (Phase 2) commits a direction on at
most 3/30 events due to the 5-minute Radar bucket resolution
limit. The other 27/30 events get the HCAF Bayesian fallback.

The 5-minute Radar resolution is an external constraint, but
the consequence is that **Phase 2 commits a direction on 27/30
events via Bayesian fallback alone, without the CSS gatekeeper
that the system design says is essential**. The "T → R = 0.77"
result on the Iran case study (Section 6.7) is a Bayesian
fallback commitment, not a CSS commitment.

**Concrete ask:** Report the Phase 2 strict-accuracy on the
sub-set of v17 events where CSS returns `is_causal = True`
(n ≤ 3). If this sub-set has 100% accuracy, the system is
sound. If it is 1/3 or 0/3, the CSS sub-system is not doing
useful work and the Phase 2 claim should be downgraded.

### W4. **The 30-event v17 selection is over-engineered.**

Section 3.6 (Data) describes six invariants. The paper claims
the BGPStream corpus contains ~7000 candidate events and the
invariants reject all but 30. The framing is "we are
data-conservative", but the consequence is that the headline
86.7% is on a curated set that may not represent the BGP-
monitoring operational surface.

**Concrete ask:** Report the 30-event composition by **incident
class, public-source coverage, and temporal spread** (year and
quarter). If 25/30 events are from 2020-2024 Cloudflare blog
posts, the system is tested on a specific narrative class.

### W5. **Minor: the headline 92.9% excludes Starlink via "excl.
NC" framing.**

The "excl. NC" 92.9% is a 28-event number (Starlink is a
single negative control). The 92.9% vs 86.7% is a 6.2 pp gap
that is meaningful at n=30. A reviewer reading only the
abstract may not realize the gap is driven by a single event.

**Concrete ask:** Report 86.7% as the primary number in the
abstract and the intro; put 92.9% in a footnote with the
"excl. NC" caveat.

---

## Recommendation

**Major Revision.** The paper's reproducibility discipline and
honest miss reporting are commendable. The v18 held-out stress
test (W1) and the CSS-anchored Bayesian fallback (W3) need
reframing before the paper can claim the dependable-systems
contribution it aspires to.

---

## Questions for the rebuttal

1. Can you report strict-accuracy on v17 events conditioned on
   `degraded_mode == False`?
2. Can you add the negative-control experiment proposed in W2?
3. Can you show the Phase 2 strict-accuracy on the n ≤ 3 events
   where CSS is causal?
4. Can you show the 30-event composition table proposed in W4?
