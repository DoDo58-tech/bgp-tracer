# Agent layer: audit of what the experiments actually show

*Status: internal audit. Not for the paper text.*

*First written 2026-10-27. Revised 2026-10-29 after the agent layer was
made load-bearing and the corpus evaluation was re-run; the findings
below that have since been resolved are marked as such, and the
measurements they were based on have been replaced.*

This document records what the agent-layer experiments measure, what
they currently show, and — importantly — which of the project's
claimed innovations are **not** yet supported by a measurement. It
exists so that the paper's claims can be checked against artefacts
rather than against intent.

## 1. What the artefacts currently say

| Artefact | What it measures | n | Result |
|---|---|---|---|
| `results/eval/agent_value_ablation_v2.json` | monolithic vs `traffic_first` vs ReAct: latency, tokens, record counts, verdict agreement | 10 / 10 / 3 | agreement `monolithic ↔ traffic_first` = **10/10 (1.00)** |
| `results/eval/component_ablation_summary.json` | six stage-level ablations, each vs full, three repeats each | 39 per arm per repeat | **reasoning $-0.094$**, Blackboard $-0.017$, HCAF $-0.009$; joint evidence, hypothesis and enrichment $+0.000$ |
| `results/eval/explainability_audit_corpus.json` | six explainability questions, agent vs monolithic | 39 | agent mean **0.927**, monolithic mean **0.282** |
| `results/eval/degradation_probe.json` | five injected faults, does the run survive | 2 per fault | all faults degrade gracefully, verdict stable |
| `results/eval/agent_loop_audit.json` | which agents have a real decide→act→observe loop | — | `ReactAgent`: autonomous loop; others: pipeline |
| `results/eval/gt_agent_full.json` | the agent's cause vs the 39-event ground-truth corpus | 39 | **$22/39$ = 0.564** |
| `results/eval/gt_rule_only.json` | the deterministic rules, no language model | 39 | **$19/39$ = 0.487** |
| `results/eval/gt_baseline_monolithic.json` | the monolithic one-shot LLM | 39 | **$4/39$ = 0.103** |

## 2. The finding that matters

> **Resolved 2026-10-29.** This section described the state of the
> pipeline before the agent's structured judgement was wired into the
> verdict decision. The agent now overrides the rule on 35 of the 39
> corpus events, and the corpus evaluation is `22/39` for the agent
> against `19/39` for the rules-only arm and `4/39` for the
> monolithic LLM. The text below is kept as the record of what the
> original finding was, and of what had to change to fix it.

**The agent layer currently changes no verdict.**

Both ablation families agree, and they agree for a reason that can be
traced in the code:

1. `EvidenceChainBuilder.determine_verdict`
   (`detectors/evidence_chain_builder.py:849`) is a **deterministic
   rule table** over four inputs: `traffic_result`,
   `routing_result`, `causal_analysis`, `bayesian_result`. It returns
   one of five fixed strings.

2. `bayesian_result` is **never populated**. `WorkflowContext`
   declares it (`workflow_engine.py:169`) and two call sites read it
   (`workflow_engine.py:1631`, `:1651`), but no code path ever assigns
   a non-`None` value. The `if bayesian_result:` branch at
   `evidence_chain_builder.py:856` is therefore dead.

3. `causal_analysis` is produced by `compute_causal_analysis`
   (`workflow_engine.py:1098`), which is also a deterministic
   threshold rule over anomaly counts and timestamps.

4. The LLM's reasoning — `context.reasoning_result`, produced by
   `run_reasoning_agent` (`workflow_engine.py:1739`) — is **never
   passed into `build_evidence_chain`**. It is written to the board
   and used for enrichment, but it does not reach the verdict.

Consequently `determine_verdict` is a function of the *detectors'
outputs alone*. The coordination layer around it adds records,
explanations and a report, but it cannot change the answer — and the
ablations confirm this empirically: removing the reasoning stage, the
joint-evidence stage, the hypothesis stage, the HCAF stage or the
enrichment stage changes **zero** verdicts.

The `monolithic ↔ traffic_first` agreement of 10/10 is the same fact
measured from the other direction.

This is not a bug. It is a design in which the *evidence plumbing* is
real and the *decision* is not yet delegated to the agent. The paper
must not claim otherwise.

## 3. Why the current numbers cannot be cited as "the agent improves accuracy"

* `agent_value_ablation_v2` compares **cost and richness**, not
  accuracy: it reports latency, tokens, record counts and verdict
  agreement. The agreement column is 1.00, which reads as "the agent
  is a no-op" rather than "the agent is better".
* `component_ablation` is under-powered: `n = 3` per arm. A zero
  verdict-change rate on 3 events cannot distinguish "the component
  does not matter" from "the corpus contains no event where it would
  matter".
* `explainability_audit_v2` measures whether *records exist*, and the
  agent arm wins (1.00 vs 0.417). But `Q4_alternative` and `Q5_gap`
  were partly satisfied by prose in the report rather than by a
  record on the board. The prose fallback has been removed and the
  audit re-run pending; the honest expectation is a lower agent score
  that reflects the records that genuinely exist.
* `agent_ground_truth.json` — the only artefact that measures
  *correctness* against external ground truth — **does not exist**.

## 4. What has to be true for the agent to be a real contribution

The agent layer can only earn the "it helps" claim if the agent's
judgement can *change* the outcome in cases where the deterministic
rule is wrong. Concretely, the pipeline needs:

1. **A falsifiable decision point.** The agent must be able to
   *override* the rule table when it has evidence the rule ignores —
   e.g. a traffic drop with no routing anomaly, where the rule says
   `traffic_only_anomaly` but the agent has a corroborated external
   explanation. Today the rule's output is the final answer.

2. **The agent's reasoning must reach the verdict.** The cheapest
   honest route is to make `build_evidence_chain` accept the
   reasoning agent's *structured* output — a proposed verdict plus
   its supporting claim IDs — and let the agent's proposal be
   compared against the rule's proposal, with the disagreement
   recorded and arbitrated. That makes `reasoning_result` a
   first-class input rather than a commentary.

3. **A ground-truth evaluation that can detect a difference.** The
   41-event Tier-A corpus with `agent_ground_truth.json` is that
   evaluation. Until it exists, no accuracy claim is possible.

4. **An ablation that is powered to see a difference.** `n = 3` per
   arm cannot. The ablation must run over the resolved GT subset
   (31 of 41 events currently resolve to a cache), which also gives
   the ablation a correctness metric rather than only a cost metric.

## 5. What the detector output actually contains (measured)

`scripts/score_signal_information.py` measures, for each detector
signal, the lift `P(signal | class) / P(signal | corpus)` over the 31
resolvable events. Lift near 1.0 for every class means the signal
carries no cause information.

| Signal | Corpus rate | Lift: hijack / outage / leak | Verdict |
|---|---|---|---|
| `traffic_available` | 0.35 | **2.42 / 0.78 / 0.00** | informative |
| `traffic_drop_ge_50` | 0.29 | **2.46 / 0.77 / 0.00** | informative |
| `outage_period_anomalies_ge_2` | 0.10 | 0.00 / **1.72** / 0.00 | informative |
| `leak_truncated` | 0.71 | 0.60 / 1.02 / 1.41 | weak |
| `routing_outage_suspected` | 0.84 | 0.68 / 1.13 / 0.99 | weak |
| `leak_count_positive` | 0.97 | 0.89 / 1.03 / 1.03 | **no information** |
| `hijack_events_positive` | 0.00 | — / — / — | **never fires** |

Three consequences that the paper has to state honestly:

1. **The leak detector saturates.** 22 of 31 events report
   `leak_count` at the 5000 truncation limit, for outages and hijacks
   alike. The leak records carry no `claimed_as` / `affected_asns`
   payload in any event, so a real leak cannot be distinguished from a
   saturated scan by inspecting the records. "There are route leaks"
   is not evidence of a route leak.

2. **The hijack detector never fires.** `origin_hijacked` and
   `forge_hijacked` are empty on all 31 events, including the 7
   labelled `origin_hijack_victim`. A hijack can only be inferred from
   the traffic profile, not read off the routing layer.

3. **`outage_score` is a constant.** It is 0.3 whenever
   `is_outage_suspected` is true and 0.0 otherwise, so it adds nothing
   beyond that boolean.

The traffic layer is therefore the only layer that separates the
classes, and it separates them on physical grounds: a leak does not
withdraw the victim's routes (no traffic impact), an outage withdraws
them and the drop spans the outage window, and a hijack also collapses
traffic but the drop does not span the window.

## 6. What the deterministic mapping achieves

`scripts/score_cause_mapping.py` scores the mapping that the evidence
chain applies, on the whole corpus, in seconds:

| Arm | n | Cause accuracy |
|---|---|---|
| deterministic rule (evidence mapping) | 31 | **0.516** |
| monolithic one-shot LLM | 31 | **0.194** |
| full agent pipeline | 31 | pending |

Per class, the deterministic mapping gets `outage` 13/18, `route_leak`
1/6, `origin_hijack_victim` 2/7. The monolithic baseline collapses to
`route_leak` on almost everything, because "route leaks" is the most
frequent phrase in the evidence it is shown.

This is the honest state of the comparison: **the coordination layer
has to beat 0.516, not 0.194.** The earlier 0.032 baseline figure was
an artefact of scoring the baseline's free-text answer by exact string
match against a label vocabulary while the agent emitted labels; both
arms now go through the same `normalize_cause_label`.

> **Updated 2026-10-29.** The three-arm corpus evaluation
> (`scripts/agent_ground_truth_eval.py`, 39 events) supersedes the
> numbers above: the full agent pipeline reaches **$22/39$ = 0.564**,
> the pure-detector rules with no language model reach **$19/39$ =
> 0.487**, and the monolithic one-shot LLM reaches **$4/39$ = 0.103**.
> The agent is therefore above the deterministic mapping, but the
> three-event gap to the rules-only arm is not significant on its own
> at $n=39$; the per-class movement it produces is the defensible
> claim.

## 7. Known blockers in the measurement infrastructure

* **Runtime.** A single `analyze_deep_from_quick` call re-runs the
  full leak detector over the BGP archive: ~3–6 minutes per event.
  41 events × 7 arms is not feasible in one session. The
  measurement must therefore either cache the *detector* output per
  event and re-run only the *agent* layer (which is what actually
  varies), or run the arms in parallel across events.
* **Cache coverage.** Only 31/41 GT events resolve to a cache. The
  10 unresolved are 2018–2024 events whose raw BGP data is not in
  the local archive; they are a data-coverage limit, not a code
  defect. The 19 `failed` entries in `logs/cachegen_gt.json` are the
  same set.
* **ReAct arm is unmeasured.** `agent_value_ablation_v2` has only
  3 ReAct records and their verdicts are the literal string
  `"unmapped:answered"`, which is not a class in the five-class
  vocabulary. The ReAct path needs its verdict normalised before it
  can be compared at all.

## 8. Plan

> **Completed 2026-10-29.** Every item below has been done. The
> numbers that resulted are in §1 above; the agent section of the
> paper is written from them, and every one is gated by
> `scripts/check_agent_paper_numbers.py`.

1. ~~Normalise the ReAct verdict into the five-class vocabulary and
   re-run the ReAct arm to a usable `n`.~~ Done.
2. ~~Split the pipeline so the **detector output is cached per event**
   and the **agent layer is re-run per arm** over that cache.~~ Done:
   the deep pipeline reuses the cached quick-phase detector output.
3. ~~Add the agent's structured reasoning output as an input to the
   verdict decision, with the rule's proposal and the agent's proposal
   both recorded on the board, and the disagreement arbitrated and
   logged.~~ Done: `determine_verdict` and `determine_cause` take the
   agent's judgement, `record_arbitration` writes both proposals, and a
   physical veto (`hard_physical_signature`) stops the agent from
   overriding direct evidence.
4. ~~Run `agent_ground_truth_eval.py` over the resolvable events for
   the full arm and the monolithic arm.~~ Done over the 39-event
   corpus, with a rules-only arm as the third comparison.
5. ~~Re-run `component_ablation` over the same events so that the
   ablation reports correctness rather than only cost.~~ Done, three
   repeats per arm, with paired bootstrap intervals.
6. ~~Re-run `explainability_audit` with the prose fallback removed.~~
   Done over the 39-event corpus.
7. ~~Write the agent section of the paper, with the measured
   numbers.~~ Done.

The finding that survived all of this is narrower than the original
hope, and it is the honest one: **multi-round reasoning is the
load-bearing stage** (removing it costs $0.094$ in accuracy, paired CI
entirely below zero), while joint evidence generation, hypothesis
generation and external enrichment change no label on this corpus.
The coordination layer's value here is auditability and resilience
rather than accuracy.

## 9. Rules this project follows for the evaluation

* No oracle filtering: the agent never sees the ground-truth label.
* The cache match is structural (window containment), not ASN-only.
* Every number in the paper is checked by
  `scripts/check_agent_paper_numbers.py` against the artefact that
  produced it, and the gate is enforced by
  `tests/test_agent_paper_numbers_gate.py`.
* Ablations report `verdict_changes` and cost; a component that
  changes no verdict is reported as such, not hidden.
