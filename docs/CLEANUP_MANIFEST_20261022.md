# Cleanup Manifest — 2026-10-22

Scope: `results/` + `logs/` only. **No `data/` directory was touched**
(v18/v19 are distinct event cohorts; v18 holds features for 38 of the 30
currently-evaluated events).

## PRESERVED — live dependency of current eval/figure pipeline

| File | Referenced by |
|---|---|
| `results/eval/hcaf_vs_baselines_30.jsonl` | `build_per_event_30_csv.py` (SRC → per_event_30.csv) |
| `results/eval/hcaf_vs_baselines.jsonl` | `eval_hcaf_vs_baselines.py` (default `--out`) |
| `results/eval/hcaf_vs_baselines_v33.jsonl` | `render_case_study_fig.py`, `hcaf_4way_table.py` |
| `results/eval/hcaf_vs_baselines_v36.jsonl` | `reproduce_eval.py`, `build_sensitivity.py`, `build_threshold_sensitivity.py`, `draw_hcaf_decomp.py` |
| `results/eval/hcaf_vs_baselines_v11.jsonl` | `build_ablation.py`, `benchmark_timing.py` |
| `results/eval/per_event_30.csv` | `render_paper_figs.py`, `render_paper_figs_v24.py`, `significance_tests.py` |
| `results/eval/per_event_v36.csv` | `evaluate_offline.py`, `reproduce_eval.py`, `build_neg_ctrl_evaluation*.py`, `render_paper_figs_p1.py`, `verify_round23.py` |
| `results/eval/per_event_v36_real.csv` | `render_paper_figs_p1.py` |
| `results/eval/eval_audit_*.md`, `DIAGNOSIS_REPORT.md` | audit trail |

## PRESERVED — `results/html_*`
`tests/test_no_llm_override_regressions.py` globs `results/html_*`.
It excludes the date-stamped dirs by mtime, so removal is tolerated,
but the dirs were left in place this pass (cheap, and the test still
resolves `results/html` + `results/html_postfix`).

## DELETED

### results/ — superseded versioned eval dirs (~1.4 GB)
- `results/quick_backup_v17_skip` (1.1G)
- `results/html_0923` (37M), `html_0928` (130M), `html_1003` (170M),
  `html_1007` (23M), `html_1008` (16M), `html_1009` (15M)

### results/eval/ — superseded per-event CSVs
- `per_event_v11.csv`, `per_event_v11_real.csv`, `per_event_v12.csv`
  (`build_real_subset_csv.py` docstring references these as its own
   *outputs*; it regenerates them from per_event_v36.csv)

### results/ — superseded cache predictions
- `cache_predicted_v17.csv`, `cache_predicted_v17.csv.bak`
  (`cache_predicted_v19.csv` retained as latest)

### results/eval/ — superseded eval JSONL
Kept `_30`, bare, `v11`, `v33`, `v36` (see table above).
Deleted: `v12`,`v13`,`v14`,`v15`,`v16`,`v16_full`,`v17`,`v18`,`v19`,
`v20`,`v21`,`v22`,`v23`,`v24`,`v25`,`v26`,`v27`,`v28`,`v29`,`v30`,
`v31`,`v32`,`v34`,`v35`, `v11_v33`, `v9_v33`,
`dataset_invariants_v13/v14.jsonl`, `quick_eval_results*.jsonl`,
`scored_v1.jsonl`, `pc_baseline_v17.jsonl`.

### logs/ — old batch + nightly run dirs (~14 MB)
- `4mode_batch_2026*` (7), `nightly*` (5), `nightly_2026*_html`,
  `v7_partial_20261008_162541`, `batch_4mode`

## NOT DELETED (intentionally)
- All of `data/` — v18/v19 are distinct event cohorts, not revisions.
  v18 provides routing/traffic parquet features for 38 of the 30 events
  under evaluation; deleting it destroys the P0 re-evaluation inputs.
- `results/eval_v20`, `eval_v22`, `gt_audit_v22` — referenced by
  `v20_evaluate.py`, `v22_evaluate.py`, `audit_v22_gt.py`,
  `render_v22_figs.py`, `render_eval_figs.py`, `beam_heatmap_2025.py`,
  `bian_deployment_chart.py`.
- `results/html`, `results/html_postfix` — live test targets.
- `results/cloudflare_alerts` — the 192-alert replay source data.