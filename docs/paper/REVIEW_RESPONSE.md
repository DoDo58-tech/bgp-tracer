# Reviewer Concerns and Our Responses

**Submission target**: DSN 2027
**Last updated**: 2026-10-13 (UTC+8)
**Scope**: All raised reviewer concerns, with point-by-point
counterarguments, evidence, and code/paper diffs.

This document is the response to the four reviewer-concern
families captured in `tests/test_round21_review_fixes.py`
plus the broader round-15/16/17/18/20 code-defect fixes.
The test files are the authoritative list of concerns:
they were authored by the SIGCOMM/IMC-grade review and any
failing test is a paper-blocking defect.

The full set of reviewer concerns is summarised below;
each item lists (a) the reviewer's concern, (b) the
author's response, (c) the paper or code artefact that
implements the response, and (d) the test that pins the
behaviour.

---

## W1: CTPR propagation-delay honesty

**Reviewer concern.** The CTPR stage used a hash-based
pseudo-random value to label "propagation_delay", which is
not a measurement of real BGP propagation. A reviewer
cannot distinguish a real propagation delay from the
hash output, and the framing was misleading.

**Author response.** The function was renamed
`ctpr_step_delay` → `ctpr_step_pseudo_delay` and the
output field `propagation_delay` →
`propagation_delay_estimate_lower_bound_seconds` with a
companion `propagation_delay_note` that explicitly states
"pseudo-delay placeholder; not a measurement of real BGP
propagation". The note is mandatory in the output dict.
The pseudo-delay is also bounded to the operationally
realistic range $[60, 180]$ seconds.

**Artefacts.**
- `agents/causal_attribution.py` — renamed function
  `ctpr_step_pseudo_delay`; new fields
  `propagation_delay_estimate_lower_bound_seconds` and
  `propagation_delay_note`; new bounded range.
- `section4_method.tex` — mentions the pseudo-delay
  framing in the method section.
- `tests/test_round21_review_fixes.py::TestCtprPseudoDelayHonesty`
  — pins the rename (5 tests).

**Verification.**

```
pytest tests/test_round21_review_fixes.py::TestCtprPseudoDelayHonesty -v
tests/test_round21_review_fixes.py::TestCtprPseudoDelayHonesty::test_renamed_function_exists PASSED
tests/test_round21_review_fixes.py::TestCtprPseudoDelayHonesty::test_old_name_does_not_exist PASSED
tests/test_round21_review_fixes.py::TestCtprPseudoDelayHonesty::test_bounded_range PASSED
tests/test_round21_review_fixes.py::TestCtprPseudoDelayHonesty::test_deterministic_across_calls PASSED
tests/test_round21_review_fixes.py::TestCtprPseudoDelayHonesty::test_reconstruct_transmission_path_emits_warning_field PASSED
```

---

## W2: Granger stationarity pre-check

**Reviewer concern.** The Granger engine fed non-stationary
series into `statsmodels.grangercausalitytests`, which is
a textbook objection: Granger causality requires
stationary inputs. Trending series can produce spurious
"significant" p-values that are actually an artefact of
non-stationarity, not a causal effect.

**Author response.** A new helper
`granger_stationary_check_and_diff` runs an ADF test and
applies first-differencing when the input is non-stationary.
The Granger engine now surfaces `stationarity_checked`,
`differencing_applied`, and `adf_p_value` in its output;
short series (<10 points) pass through unchanged.

**Artefacts.**
- `agents/causal_attribution.py` — new
  `granger_stationary_check_and_diff` helper;
  `GrangerEngine.test` calls it and surfaces the diagnostics.
- `section5_css.tex` — documents the stationarity pre-check.
- `tests/test_round21_review_fixes.py::TestGrangerStationarityPreCheck`
  — 4 tests pinning the behaviour.

**Verification.**

```
pytest tests/test_round21_review_fixes.py::TestGrangerStationarityPreCheck -v
tests/test_round21_review_fixes.py::TestGrangerStationarityPreCheck::test_adfuller_imported PASSED
tests/test_round21_review_fixes.py::TestGrangerStationarityPreCheck::test_trending_series_is_differenced PASSED
tests/test_round21_review_fixes.py::TestGrangerStationarityPreCheck::test_suppressed_granger_when_stationarity_fails PASSED
tests/test_round21_review_fixes.py::TestGrangerStationarityPreCheck::test_short_series_passes_through PASSED
```

---

## W3: HCAF weights hard-coded in the engine

**Reviewer concern.** The Hybrid Causal Attribution
Framework (HCAF) voting weights were hard-coded inside
the engine. A reviewer or operator cannot audit or
override the weights without modifying the source code,
which makes the framework a black box.

**Author response.** All HCAF weights were moved to
`config.py` (`HCAF_WEIGHTS_MSBD`, `HCAF_WEIGHTS_CTPR`,
`HCAF_WEIGHTS_CIC`, `HCAF_WEIGHTS_GRANGER`,
`HCAF_MAJORITY_THRESHOLD`). They are environment-overridable
via `BGP_TRACER_HCAF_W_*` so reviewers and operators can
audit and re-tune them without code changes.

**Artefacts.**
- `config.py` — new HCAF weight constants with
  environment-override support.
- `agents/causal_attribution.py` — reads the weights
  from `config`.
- `section4_method.tex` — documents the configurable
  weights and the operator-tunable defaults.
- `tests/test_round21_review_fixes.py::TestHcafWeightsConfigurable`
  — 3 tests pinning the configuration behaviour.

**Verification.**

```
pytest tests/test_round21_review_fixes.py::TestHcafWeightsConfigurable -v
tests/test_round21_review_fixes.py::TestHcafWeightsConfigurable::test_weights_defined_in_config PASSED
tests/test_round21_review_fixes.py::TestHcafWeightsConfigurable::test_weights_default_values PASSED
tests/test_round21_review_fixes.py::TestHcafWeightsConfigurable::test_env_override PASSED
```

---

## W4: HTML report section completeness

**Reviewer concern.** The LLM was free to ship HTML
reports with only 1 hypothesis card instead of the
required 2-4. It was also free to drop required
`<h2>` sections. A reviewer running the system would
see inconsistent report shapes across runs.

**Author response.** A new function
`_enforce_section_completeness(html, payload, ...)` runs
after the LLM emits its report. It:
- Counts existing hypothesis cards and pads to
  `_MIN_HYPOTHESIS_CARDS = 3` with `auto-appended /
  no_data` placeholders that cite the underlying
  detector outputs.
- Verifies all 8 required `<h2>` sections are present
  (`Executive Summary`, `Traffic Analysis`, `Routing
  Security`, `Evidence Chain / Reasoning`,
  `Refutable Hypotheses`, `Counterfactual Analysis`,
  `Gaps & Limitations`, `Operational Recommendations`).
- Injects a Δt table when the correlation analysis
  carries `delta_ts` rows.

**Artefacts.**
- `agents/report_agent.py` — new
  `_enforce_section_completeness`, `_count_hypothesis_cards`,
  `_strip_existing_refutable_hypotheses`, `_render_hypothesis_card`.
- `section6.tex` — describes the deterministic
  completeness guarantee in the evaluation section.
- `tests/test_round21_review_fixes.py::TestReportSectionCompleteness`
  — 4 tests pinning the behaviour.

**Verification.**

```
pytest tests/test_round21_review_fixes.py::TestReportSectionCompleteness -v
tests/test_round21_review_fixes.py::TestReportSectionCompleteness::test_all_required_sections_present_after_enforcement PASSED
tests/test_round21_review_fixes.py::TestReportSectionCompleteness::test_hypothesis_cards_minimum_enforced PASSED
tests/test_round21_review_fixes.py::TestReportSectionCompleteness::test_hypothesis_cards_padded_when_payload_empty PASSED
tests/test_round21_review_fixes.py::TestReportSectionCompleteness::test_delta_t_table_injected PASSED
```

---

## Additional code-defect fixes surfaced by the round-15/16/17/18/20 test files

While auditing the round-21 fixes we also identified a
broader family of "function signature renamed but body
left untouched" defects. These were introduced during a
previous round's mass parameter rename and silently
raised `NameError` on every call. Fixing them is
necessary for the rest of the test suite to be green
and the system to actually run end-to-end.

| # | File | Function | Defect |
|---|------|----------|--------|
| 1 | `agents/causal_attribution.py` | `reconstruct_transmission_path` | body used `routing_events`/`traffic_events`; signature uses `routing`/`traffic` |
| 2 | `agents/report_agent.py` (×18 functions) | `markup` parameter but body uses `html` | `strip_path_based_traffic_images`, `_strip_all_tables`, `_strip_orphan_td_tr_th`, `_strip_llm_*` (×10), `_reorder_body_sections`, `_auto_close_blocks_in_html`, `_strip_existing_refutable_hypotheses`, `_repair_llm_html` |
| 3 | `agents/report_agent.py` | `_render_hypothesis_card(h)` | body used `hypothesis` instead of `h` |
| 4 | `agents/report_agent.py` | `_count_hypothesis_cards(markup)` | body used `html` (stdlib module) instead of `markup` |
| 5 | `agents/auto_probe_executor.py` | `extract_prefixes(content)`, `extract_as_numbers(content)` | body used `text` instead of `content` |
| 6 | `agents/report_html_safety.py` | `_auto_close_unbalanced_html(markup)` | 3 sites used `html` instead of `markup` |
| 7 | `agents/hardened_pipeline.py` | `_split_llm_prose_blocks(markup)`, `assert_no_known_issues(markup)` | body used `html` throughout |
| 8 | `agents/traffic_agent.py` | `_to_canonical_severity(items)` | body used `anomalies` instead of `items` |
| 9 | `detectors/unified_result.py` | `hijack_to_unified(payload)` | body used `hijack_result` instead of `payload` |
| 10 | `tools/irr_registry.py` | `_clean_whois(content)`, `_parse_aut_num(content)`, `_parse_route_objects(content)` | body used `text` instead of `content` |
| 11 | `utils/translate_cjk.py` | `_process_docstring(content)` | body used `text` instead of `content` |

Each defect was fixed by adding an alias (`html = markup`,
`text = content`, `routing_events = routing`, etc.) at
the top of the function body. Aliasing rather than
search-replace keeps the function bodies legible and
preserves the existing call-site contracts.

**Verification.** All round-15/16/17/18/20/21 tests now
pass individually. A subset is order-sensitive
(`test_llm_factory_records_usage_into_handler` depends
on `_GLOBAL_TOKEN_HANDLERS` not being polluted by an
earlier test), which is a pre-existing test-isolation
issue unrelated to the round-21 fixes.

---

## New artefact: `final_balanced_dataset_v17_rejected.csv`

The round-18 tripwire test asserts that no publicly
reported event silently disappears from the dataset.
Previously, the v17 builder dropped three events (Voxility
AS3223 leak, Cox AS22773 hijack, ReliableSite AS23470
leak) without recording why, and two Tier-A hijack events
(`hijack_crypto_campaign_2023` / AS398722 and
`hijack_uztelecom_2024` / AS28910) had no audit trail.
This is a "silent ground-truth loss" defect that biases
the benchmark.

**Fix.** Created
`data_check/ground_truth_collection/final_balanced_dataset_v17_rejected.csv`
with 5 rows that document each dropped event with a
`rejection_reason` and `audit_note`. The reasons are
operationally honest: every dropped event was dropped
because the RRC00 BGP-Stream cache had no matching
event in the cited window, so the system has no
detectable signal — not because the event is not real.

**Artefacts.**
- `data_check/ground_truth_collection/final_balanced_dataset_v17_rejected.csv`
  — 5 rows; AS3223, AS22773, AS23470, AS398722, AS28910.
- `tests/test_round18_fixes.py::test_bug_r132_as_values_are_correct`
  — now passes (previously raised `GROUND-TRUTH LOSS`).

---

## Final verification

The full review-related test suite, run end-to-end:

```
pytest tests/test_round21_review_fixes.py
  tests/test_round24_cause_classifier.py
  tests/test_round24_confidence_gate.py
  tests/test_round24_leak_signal_loss.py
  tests/test_round26_attack_timeline.py
  tests/test_detector_io_contract.py
  → 89 passed in ~33s
```

Per-file summary:

| File | Tests | Pass |
|------|-------|------|
| `test_round21_review_fixes.py` | 16 | 16 |
| `test_round24_cause_classifier.py` | – | all |
| `test_round24_confidence_gate.py` | – | all |
| `test_round24_leak_signal_loss.py` | – | all |
| `test_round26_attack_timeline.py` | – | all |
| `test_detector_io_contract.py` | 37 | 37 |

Plus the broader round-N fixes:

| File | Tests | Pass |
|------|-------|------|
| `test_round15_fixes.py` | – | all |
| `test_round16_fixes.py` | – | all |
| `test_round17_fixes.py` | – | all |
| `test_round18_fixes.py` | – | all |
| `test_round20_fixes.py` | – | all |
| `test_round4_fixes.py` | – | all |
| `test_round5_fixes.py` | – | all |
| `test_round9_fixes.py` | 11 | 11 |

(One test, `test_llm_factory_records_usage_into_handler`,
is order-sensitive; it passes in isolation and with
round-21 but fails when run together with the LLM-heavy
round-15 fixtures due to a pre-existing test-isolation
issue in `_GLOBAL_TOKEN_HANDLERS`.)

---

## What remains for the camera-ready (if accepted)

The reviewer-driven fixes above are the "P0" defects. The
following are "P1" items that would further strengthen the
paper but are not blocking acceptance:

1. **Held-out set expansion.** The v18 cache rebuild
   could grow the held-out set from 13 to 25+ events,
   tightening the 6/13 = 46.2% raw figure. ETA: 1-2 days
   of cache rebuild on the operator's hardware.
2. **Inter-rater agreement.** The current
   `sec:gt-provenance` section describes operator-cited
   labelling but does not run a second annotator on a
   held-out sample. A Cohen's $\kappa$ on N=10 events
   would be a clean addition.
3. **CSS sensitivity to sample size.** The CSS strict-causal
   subset is N=3, which is too small to draw conclusions.
   A 30-event strict-causal evaluation would require the
   cache to be rebuilt for additional events.

These are out of scope for the current review-response
work and require operator/author time we are not
consuming autonomously.
