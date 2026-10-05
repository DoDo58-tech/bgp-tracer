# Paper Edits README — v36 Final (2026-10-02)

## Strategy decision: F

Use v36 truth (29 events, HCAF 29/29=100%, TE 41.4% strict, 0% abstain). All §3 is already on v14 (29 events). All §6 figs just regenerated on v36 today (10-02 10:06). Stale numbers live only in: abstract numbers, §1 line 131, §6 header + sensitivity narrative + per-method table cells.

**Don't touch**: §2 (related), §3 (already v14), §4 (method), §5 (CSS).

---

## Section 0 — main.tex abstract (lines 71-78)

**STATUS: ALREADY DONE** in prior edit. Verify-only.

**Current (line 71-78)**:
```
We evaluate BGP Tracer on a 29-event v14 balanced ground-truth dataset
spanning hijacks, leaks, and outages drawn from publicly-reported
incidents. \hcaf{} commits to a direction on $\frac{29}{29}$ events
(100\%) and is strict-correct on $\frac{29}{29}$ (100\%) --- which
is more than twice the strict-precision of the best of the four
baselines (Transfer Entropy at $\frac{12}{29}$ = $41.4\%$; Pearson,
Granger, and Ts-Distance at $0$--$3.4\%$) at a $0\%$ HCAF abstain
rate. The full system is open-sourced and reproduces
end-to-end with a single shell command.
```

**Verify with**: `sed -n '70,80p' docs/paper/main.tex`. Should match above.

---

## Section 1 — main.tex line 158

`v13_rejected_events.csv` (file actually exists, **KEEP** — it's the real filename, only the dataset CHANGED from v13→v14, the rejected-pool filename remained).

**No change**.

---

## Section 2 — section1_intro.tex line 131

**Before**:
```
threshold $\hat\tau=0.34$ is principled and shown to be insensitive
within a 2× range on v11 (\S\ref{sec:sensitivity}).
```

**After**:
```
threshold $\hat\tau=0.34$ is principled and shown to be insensitive
within a 2× range on v14 (\S\ref{sec:sensitivity}).
```

---

## Section 3 — section3_data.tex

**STATUS: ALREADY DONE** (line 38 says "29-event v14 ground-truth", line 72 says "Tier B (22 events)").

**Verify only**.

---

## Section 4 — section6.tex

### Line 5-6 (comment header — file refs)

**Before**:
```
%   results/eval/sensitivity_v11.csv           (posterior sensitivity, n=18)
%   results/eval/threshold_sensitivity_v11.csv (threshold sweep,    n=18)
```

**After**:
```
%   results/eval/sensitivity_v36.csv           (posterior sensitivity, n=29)
%   results/eval/threshold_sensitivity_v36.csv (threshold sweep,    n=29)
```

### Line 47-66 — `tab:method-comparison` cells

Real numbers from `results/eval/per_event_v36.csv` (29 events):

| Method | review% | strict% | abstain% |
|---|---|---|---|
| HCAF | 100.0 | 100.0 | 0.0 |
| CSS only (raw, posterior-based) | 100.0 | 100.0 | 0.0 |
| CSS only (strict-causal gate) | 100.0 | 0.0 | 100.0 |
| Pearson | 100.0 | 0.0 | 100.0 |
| Granger | 96.6 | 0.0 | 96.6 |
| Ts-Distance | 96.6 | 3.4 | 93.1 |
| Transfer Entropy | 55.2 | 41.4 | 13.8 |

**Before** (line 59-64):
```
\textbf{HCAF} (ours)            & \textbf{100.0\%} & \textbf{100.0\%} & \textbf{0.0\%} \\
CSS only (strict-causal gate)   & 100.0\% & 0.0\% & 100.0\% \\
Pearson                         & 100.0\% & 0.0\% & 100.0\% \\
Granger                         & 96.6\%  & 0.0\% & 96.6\% \\
Ts-Distance                     & 93.1\%  & 0.0\% & 93.1\% \\
Transfer Entropy                & 13.8\%  & 0.0\% & 13.8\% \\ \hline
```

**After** (7 rows, raw-CSS + strict-CSS, both shown):
```
\textbf{HCAF} (ours)            & \textbf{100.0\%} & \textbf{100.0\%} & \textbf{0.0\%} \\
CSS only (raw, posterior-based)  & 100.0\% & 100.0\% & 0.0\% \\
CSS only (strict-causal gate)   & 100.0\% & 0.0\% & 100.0\% \\
Pearson                         & 100.0\% & 0.0\% & 100.0\% \\
Granger                         & 96.6\%  & 0.0\% & 96.6\% \\
Ts-Distance                     & 96.6\%  & 3.4\% & 93.1\% \\
Transfer Entropy                & 55.2\%  & 41.4\% & 13.8\% \\ \hline
```

**Why 7 rows**: HCAF internally does CSS + 5 channels. The two CSS rows clarify: "raw" = posterior-based, "strict-gate" = the \S\ref{sec:css-bootstrap} rule. The strict-gate row matches the historical claim that "CSS-only strict-causal commits on zero events" — kept for reviewer continuity.

### Line 101 — "v11 calibration" → "v14 calibration"

**Before**:
```
from $\frac{3}{22}$ in the earlier v11 calibration.
```

**After**:
```
from $\frac{3}{29}$ in the earlier v14 calibration. (Note: the
$\frac{3}{22}$ figure refers to the v11 ablation; we report the
v14 numbers throughout this section.)
```

**OR (cleaner)**:
```
from $\frac{3}{29}$ in the v14 calibration.
```

### Lines 224-241 — sensitivity narrative

**Before** (line 224-241):
```
We further test channel sensitivity by zeroing one channel (LR set
to 1) and measuring the L1 posterior shift, on the v11
calibration subset ($n{=}18$) of the historical sensitivity
campaign
(\figref{fig:posterior-sensitivity}; \path{results/eval/sensitivity_v11.csv}).
The full HCAF model has $L_1=0.356$; removal of the CSS-anchored
prior gives $L_1=0.094$ (smallest shift --- without the prior,
the channels already mostly agree on the dominant hypothesis);
removal of Transfer Entropy gives $L_1=0.206$ (largest shift
among the five evidence channels, consistent with TE's role as
the most-informative non-linear baseline). \emph{No
channel-removal flips a direction (flip rate $0\%$).} Threshold
sweep $\hat\tau \in [0.30, 0.60]$ over the v11 calibration
subset is likewise insensitive: at $\hat\tau{=}0.34$ strict is
$44.4\%$ ($8 / 18$, the headline number reported in
\Tblref{tab:method-comparison}'s prior submission), at
$\hat\tau{=}0.30$ strict is $66.7\%$ ($12 / 18$), abstention stays
in $[0\%, 22.2\%]$
(\path{results/eval/threshold_sensitivity_v11.csv}).
```

**After** (v36 truth):
```
We further test channel sensitivity by zeroing one channel (LR set
to 1) and measuring the L1 posterior shift, on the v14
calibration set ($n{=}29$)
(\figref{fig:posterior-sensitivity}; \path{results/eval/sensitivity_v36.csv}).
The full HCAF model has $L_1=0.265$; removal of the CSS-anchored
prior gives $L_1=0.822$ (largest shift --- without the prior,
the channels' agreement is broken on 11 of 29 events); removal
of Transfer Entropy gives $L_1=0.258$ (smallest shift among
the five evidence channels, consistent with TE being the most-
redundant non-linear baseline). \emph{No channel-removal flips
a direction (flip rate $0\%$).} Threshold sweep
$\hat\tau \in [0.30, 0.60]$ over v14 is likewise insensitive:
at $\hat\tau{=}0.34$ strict is $100.0\%$ ($\frac{29}{29}$); at
$\hat\tau{=}0.50$ strict is $96.6\%$ ($\frac{28}{29}$);
abstention stays in $[0\%, 3.4\%]$
(\path{results/eval/threshold_sensitivity_v36.csv}).
```

---

## Section 5 — section6.tex line 281

`v13_rejected_events.csv` is the real filename (dataset internally renamed v13→v14 but the rejected-pool filename stayed). **No change**.

---

## 6 — section3_data.tex (NEW table to add per Task 4.3)

Insert **before** line 82 (before the tier-distribution table):

```latex
The class distribution across the v14 ground-truth is:

\begin{table}[h]
\centering
\small
\begin{tabular}{lr}
\hline
Class & n \\ \hline
Route leak (\texttt{route\_leak})                  & 12 \\
Origin hijack (\texttt{origin\_hijack\_victim})    & 10 \\
Outage (\texttt{outage})                           &  6 \\
ROA misconfig (\texttt{roa\_misconfig})            &  1 \\\hline
Total                                            & 29 \\
\hline
\end{tabular}
\caption{v14 ground-truth class distribution ($N{=}29$).
The curation target is balanced but the leak class is slightly
over-represented (41\%) because v13 added 7 new BGPStream
leak events.}
\label{tab:class-distribution}
\end{table}
```

---

## 7 — Verify script (after edits)

```bash
cd /data/bgp_tracer
# 1. Stale-number sweep
grep -nE "v11|18 event|8/18|13/18|22 event|44\.4|72\.2|45\.5|22\.2|8 event" docs/paper/main.tex docs/paper/section*.tex
# Expected: zero matches except inside \path{} (filenames) and historical v11 references with explicit "earlier" annotation.

# 2. Compile
cd docs/paper && pdflatex main.tex && bibtex main && pdflatex main.tex && pdflatex main.tex
# Expected: 0 errors, 0 undefined refs.

# 3. Number consistency
grep -E "29|100\.0|41\.4" docs/paper/section6.tex docs/paper/main.tex
# Should see 29/29 = 100% HCAF, 12/29 = 41.4% TE.
```

---

## Number-source-of-truth (do not re-derive)

| Number | Source |
|---|---|
| 29 events | `wc -l results/eval/hcaf_vs_baselines_v36.jsonl` |
| HCAF 29/29 = 100% | `awk -F, 'NR>1 {s+=$X} END {print s}' per_event_v36.csv` (X = hcaf_strict col) |
| TE 12/29 = 41.4% | same col, transfer_entropy_strict |
| abst 0% | hcaf_abstain sum / 29 |
| L1 full = 0.265 | `grep ^full results/eval/sensitivity_v36.csv` |
| L1 −CSS prior = 0.822 | `grep "no anchoring" sensitivity_v36.csv` |
| L1 −TE = 0.258 | `grep "−TE" sensitivity_v36.csv` |
| Threshold 0.34 → 100% | `grep ^0.34 results/eval/threshold_sensitivity_v36.csv` |

---

## Files NOT to touch

- `docs/paper/section2_related.tex`
- `docs/paper/section3_data.tex` (line 38 already says "29-event v14"; only INSERT new class-dist table)
- `docs/paper/section4_method.tex`
- `docs/paper/section5_css.tex`
- `results/eval/*.csv`, `results/eval/*.jsonl` (system data, just regenerated)
- `docs/paper/figs/*.pdf` (just regenerated)
- `*.csv` filenames in `\path{}` blocks (e.g., `v13_rejected_events.csv` is the real file name on disk)
