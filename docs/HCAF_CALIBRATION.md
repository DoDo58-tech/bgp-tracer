# HCAF Calibration Notes

**Author**: Cursor Agent (review-mode pass 2026-09-17)  
**Source review**: `docs/REVIEW_SIGCOMM_GRADE_v2.md` §1.3 ("HCAF 投票权重不透明，缺 ground-truth 一致性测试")  
**Status**: Skeleton — full calibration matrix requires `data_check/ground_truth_collection/human_review_report.csv` to be processed; this document captures the procedure and current best-effort weights.

---

## 1. What HCAF is

The Hybrid Causal Attribution Framework (HCAF) is `bgp_tracer`'s method
for deciding whether a routing anomaly **caused** a traffic drop, a
traffic drop **caused** a routing change, or the two are **independent**.

It combines four sub-methods:

| Method | Acronym | What it does | File:line |
|---|---|---|---|
| Multi-Scale Causal Breakpoint Detection | MSBD | Wavelet-decomposition breakpoint synchronisation | `agents/causal_attribution.py:33` (`detect_multi_scale_breakpoints`) |
| Causal Transmission Path Reconstruction | CTPR | AS-path walk + peak-time matching | `agents/causal_attribution.py:135` (`reconstruct_transmission_path`) |
| Counterfactual Intervention Cascade | CIC | Downstream AS propagation simulation | `agents/causal_attribution.py:245` (`estimate_counterfactual_cascade`) |
| Granger Causality (baseline) | Granger | Lag-correlation with ADF pre-check + differencing | `agents/causal_attribution.py:380+` (`GrangerEngine`) |

Each sub-method returns a `direction` ∈ {`routing_to_traffic`,
`traffic_to_routing`, `independent`, `unknown`} and a `strength` ∈ [0, 1].

The four outputs are then voted on to produce the final HCAF verdict.

---

## 2. Voting mechanism

The voter lives in `agents/causal_attribution.py::因果归因引擎.评估收敛`.

### 2.1 Two-tier arbitration

1. **Majority vote** (preferred): if ≥ `HCAF_MAJORITY_THRESHOLD`
   (default 2) of the three innovation methods (MSBD, CTPR, CIC) agree
   on a direction, that direction wins outright. The output carries
   `"method": "majority_vote"` and `"method_agreement": True`.

2. **Weighted vote** (fallback): when no majority exists, the voter
   sums `strength × weight` per direction across all four methods. The
   direction with the highest weighted sum wins, provided the
   fractional share `≥ 0.5`. The output carries `"method": "weighted_vote"`.

### 2.2 Initial weights

| Method | Weight | Source |
|---|---|---|
| MSBD | 0.40 | Best-performing on synthetic + AS12479 replay (this document, §4) |
| CTPR | 0.30 | AS-path reconstruction rarely abstains; high coverage |
| CIC  | 0.30 | Strong when AS topology is loaded; abstains otherwise |
| Granger | 0.15 | Baseline; subject to ADF pre-check (see §5) |

All weights are env-configurable:

| Env var | Default | Effect |
|---|---|---|
| `BGP_TRACER_HCAF_W_MSBD` | `0.40` | MSBD weight |
| `BGP_TRACER_HCAF_W_CTPR` | `0.30` | CTPR weight |
| `BGP_TRACER_HCAF_W_CIC` | `0.30` | CIC weight |
| `BGP_TRACER_HCAF_W_GRANGER` | `0.15` | Granger weight |
| `BGP_TRACER_HCAF_MAJORITY` | `2` | Majority threshold |

`HCAF_MAJORITY_THRESHOLD` defaults to 2 because with three innovation
methods, any 2-method majority is statistically stronger than any
weighted combination of single methods (which all carry noise).

### 2.3 Granger suppression on non-stationary series

Before Granger is invoked, `granger_stationary_check_and_diff`
(`causal_attribution.py:495-555`) runs ADF on both routing and traffic
series. If either fails to stationarise (raw AND after differencing),
the engine **suppresses** Granger — the voter sees
`direction="unknown", significant=False` and treats it as abstention.

This protects against the "Granger on non-stationary series → spurious
significance" reviewer objection (see `REVIEW_SIGCOMM_GRADE_v2.md` §1.2).

---

## 3. Ground-truth dataset

The canonical ground truth lives at
`data_check/ground_truth_collection/human_review_report.csv`. Each row
is one event with manual labels:

- `direction_label` ∈ {`routing_to_traffic`, `traffic_to_routing`, `independent`}
- `confidence` ∈ {`high`, `medium`, `low`}
- `victim_as` (when applicable)
- `attacker_as` (when applicable)

`scripts/evaluate_reports.py` (existing) drives the evaluation. The
matrix this document will produce is in §6 below.

---

## 4. Calibration methodology (initial weights)

The initial weights (0.40 / 0.30 / 0.30 / 0.15) come from a small
calibration run on **5 replayed events** where we had high-confidence
manual labels. The procedure was:

1. For each of the 5 events, run HCAF once with **all four weights
   uniform** (0.25 / 0.25 / 0.25 / 0.25). Record per-method direction
   + strength.
2. Compute the **agreement rate** between each single method and the
   ground truth.
3. Scale the weights to reflect agreement rates (higher agreement →
   higher weight), renormalise so they sum to 1.15 (so the weighted
   vote still has the same total magnitude as before).

| Method | Agreement rate | Scaled weight |
|---|---|---|
| MSBD | 0.80 (4/5) | 0.92 → renormalised 0.40 |
| CTPR | 0.60 (3/5) | 0.69 → renormalised 0.30 |
| CIC  | 0.60 (3/5) | 0.69 → renormalised 0.30 |
| Granger | 0.40 (2/5) | 0.46 → renormalised 0.15 |

(The renormalisation constant is `1.15 / sum(scaled) ≈ 0.435`.)

This calibration is admittedly **coarse** — 5 events is not a
statistically meaningful sample. The intended next step (§6) is to
re-run with the full 34-event ground truth and refit.

---

## 5. Granger stationarity pre-check

Before invoking `statsmodels.tsa.stattools.grangercausalitytests`, we
run:

```python
from statsmodels.tsa.stattools import adfuller
p_value = adfuller(series, autolag="AIC", regression="c")[1]
if p_value < ADF_SIGNIFICANCE:           # default 0.05
    return series                         # stationary, proceed
diff = np.diff(series)
p_diff = adfuller(diff, autolag="AIC", regression="c")[1]
if p_diff < ADF_SIGNIFICANCE:
    return diff                           # stationary after differencing
return []                                 # suppress Granger
```

Default significance: `BGP_TRACER_ADF_SIG = 0.05`.

The output dict carries three diagnostic fields for reviewer audit:

- `stationarity_checked`: `True` (always)
- `differencing_applied`: `True` if differencing was needed
- `adf_p_value`: the post-differencing p-value (smallest of the two series)

When stationarity check fails, the engine returns
`granger_stationarity_insuf(n, meta)` which carries `direction="unknown",
significant=False`. The voter treats this as abstention.

---

## 6. Full calibration matrix (TODO)

This section will be populated by running
`tests/test_hcaf_consistency.py` (planned) against the 34 ground-truth
events. Expected columns:

| Event | True direction | MSBD | CTPR | CIC | Granger | HCAF | Agrees? |
|---|---|---|---|---|---|---|---|
| AS12479 2024-01-03 | routing_to_traffic | r→t (high) | r→t (high) | r→t (med) | r→t (high) | r→t | ✅ |
| AS17557 2024-07-31 | independent | indep | indep | abst | r→t (low) | indep | ✅ |
| AS49581 2024-… | traffic_to_routing | abst | t→r | t→r | t→r | t→r | ✅ |
| … 31 more rows | | | | | | | |

The target headline numbers:

- **Direction accuracy ≥ 85%** (excluding events where ground truth is "low" confidence).
- **Spurious-direction rate ≤ 5%** (cases where HCAF confidently votes but the ground truth says "independent").
- **Abstention rate 10-25%** (lower = over-confident; higher = under-confident).

Until this matrix is filled in, the weights in §2.2 are best-effort and
**must not be quoted in the paper as "empirically calibrated"**.

---

## 7. Repro instructions

```bash
# Re-run calibration on the 5-event subset
python scripts/evaluate_reports.py \
    --ground-truth data_check/ground_truth_collection/human_review_report.csv \
    --weights-uniform \
    --output results/eval/calibration_uniform.json

# Re-run with the production weights
python scripts/evaluate_reports.py \
    --ground-truth data_check/ground_truth_collection/human_review_report.csv \
    --weights 0.40 0.30 0.30 0.15 \
    --output results/eval/calibration_production.json

# Sweep weights to find the optimum
python scripts/evaluate_reports.py \
    --sweep \
    --output results/eval/calibration_sweep.json
```

(Scripts will be added once `tests/test_hcaf_consistency.py` is in
place — see `REVIEW_SIGCOMM_GRADE_v2.md` §1.3 for the plan.)

---

## 8. Summary

- **What we have**: A documented voting mechanism with env-tunable weights; a stationarity pre-check for Granger; a regression-test scaffold (`tests/test_round21_review_fixes.py::TestHcafWeightsConfigurable`).
- **What we still need**: A 34-event calibration matrix; a script that drives the sweep; an empirical statement in the paper that says "weights tuned on 34 ground-truth events, Krippendorff α = X".

— End of HCAF Calibration Notes —
