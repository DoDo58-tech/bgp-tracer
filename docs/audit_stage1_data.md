# Pipeline Audit — Stage 1 (dataset, caches, ground truth)

Audit date: 2026-10-30. Scope: the data line from raw RRC00 updates to the
cached detector outputs that the arbitration and the agent consume.

## Findings

### F1 (critical, fixed) — evaluation resolved degraded caches

`scripts/v22_evaluate.py` read the event window from the columns
`start_time_utc` / `end_time_utc`. The v19+ ground-truth files use
`start_utc` / `end_utc`. The reader therefore resolved events with only the
calendar date, which fell through to the same-date fallback in
`agents/cache_resolution.py` and selected a *degraded* cache for the same
day instead of the one measured over the event's actual window.

Effect on the v21 corpus: Top-1 0.294, macro-F1 0.319.
Effect after the fix: Top-1 0.471, macro-F1 0.504.

Two caches encoded the same window under different filename separators
(`_` vs `T`). The `T`-separated files were produced by an older detector
build and carry an empty hijack channel and a leak count pinned at the
detector's truncation cap. `scripts/prune_stale_caches.py` moved the 32
stale twins to `results/quick/stale/`; the corpus now holds one file per
window.

### F2 (critical, fixed) — `origin_hijacking` was 100% false positives

`detectors/hijack/hijack_detector_core.py` classified an announcement as
`origin_hijacking` when the announced prefix was **not** recorded in the
RouteViews prefix-to-AS snapshot and the origin AS was the target. A prefix
the snapshot does not cover is *unknown*, not *foreign*: the target
announcing it is not evidence that the target stole it.

Measured on `outage_rogers_canada_2022` (AS812, 2022-07-08): 48 076
"attacker" alerts, of which **0** of the first 3 000 prefixes were present
in the snapshot. The channel fired on all 30 scored events, in every case
with the target AS as the claimed origin and 99–100 % of entries lacking a
recorded legitimate origin. It carried no discriminative information.

The classifier now distinguishes three states — owned, foreign, unknown —
and only the `foreign` state can produce an `origin_hijacking` verdict.
Re-running the same window gives 3 234 victim alerts (unchanged) and 83
attacker alerts instead of 48 076.

### F3 (fixed) — the leak count was pinned at the truncation cap

The leak detector caps its itemised list at 5 000 records. In 100 of the
227 caches the count sat exactly on that cap, so every such window carried
the same count and the number was an artefact of the cap. The records were
also mostly re-announcements of the same route: in one cache the 5 000
records covered 4 137 distinct (prefix, AS-path) pairs.

`agents/report_agent.py` now counts **distinct leaking routes** (prefix +
AS-path + claimed origin) instead of records, and keeps the detector's
uncapped announcement total separately as `leak_announcement_count`.

### F4 (open, measured) — the leak detector does not separate leaks from outages

The leak detector asks "is this AS-path unusual for the AS that announced
it?". The same question is answered yes by an outage, because a collapsing
AS announces a small, perturbed set of paths through unfamiliar peers.

Measured on the v21 corpus:

* the detector fires on 18/18 outages, 11/11 leaks and 12/12 hijacks —
  100 % of every class;
* no threshold in [0.05, 0.40] separates them: the median distinct-leak
  count for outages (642–3 025) exceeds that for true leaks (443–2 727) at
  every threshold below 0.20;
* re-scoring with the prefix-to-AS snapshot ("the announced prefix belongs
  to a different AS") does not separate them either: 18.8 mismatch
  prefixes per outage event against 13.1 per leak event;
* the path-probability model is a single AS-relationship snapshot (period
  202506) applied to events from 2018 through 2025, so events outside that
  period are scored against a topology that did not hold at the time.

The consequence is that `route_leak` has precision 0.22 on the v21 corpus.
This is a property of the detector's signal, not of the arbitration.

### F5 (open, documented) — the paper describes a valley-free test that the
### code does not implement

§4 states that the leak detector "applies the valley-free test to the AS
path and scores the residual candidates with a path-probability model".
No valley-free validation exists in the detector; the only test applied is
the path-probability comparison (`detection_method: "PathProb"`). The
probability model is the stable-paths model, whose likelihood ratio does
encode the valley-free preference, so the mechanism is present in effect
but not as an explicit test. The paper text has to be corrected.

### F6 (fixed) — the ground truth is well curated

`data/groundtruth_v19/candidate_metadata.jsonl` carries 28 candidates, all
at evidence tier A, each with a source URL, a victim AS and a valid time
window. Candidates that failed verification are kept in
`data/groundtruth_v19/rejected/` with `rejected_with_evidence.json`.

`data_check/ground_truth_collection/final_balanced_v21.csv` holds 41 rows
(18 outage, 11 route leak, 12 origin hijack victim). The two rows dropped
from the 39-event evaluation corpus are the CANTV 2024-08-01 pair, which
carries two different cause labels for one (ASN, window) and therefore
cannot be scored twice against a single measurement.

### F7 (open) — the leak detector's model is not period-matched

Only one path-probability model is available
(`/data/PathProb/test_data/prob_inference/result/202506/pathprob.txt`), and
`detectors/leak/leak_detector.py` loads the first existing path in
`config.PATHPROB_SEARCH_PATHS` regardless of the event's date.

## New tooling

| Script | Purpose |
| --- | --- |
| `scripts/build_detector_ablation.py` | Detector ablation computed from the real cached outputs |
| `scripts/cache_hygiene_audit.py` | Duplicate windows, degraded caches, saturated leak channels |
| `scripts/prune_stale_caches.py` | Move stale duplicate-window caches aside (reversible) |
| `scripts/leak_threshold_sensitivity.py` | Measured separability of the leak threshold |
| `scripts/leak_temporal_mismatch.py` | Per-year behaviour of the leak detector |
| `scripts/leak_origin_mismatch.py` | Re-scoring leaks against the prefix-to-AS snapshot |
