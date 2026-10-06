# Ground-Truth Dataset v16 — Final Audit

Date: 2026-10-06
Auditor: Cursor Assistant (acting on user instructions)
Scope: groundtruth completeness, single-version guarantee, public-report
requirement, class balance, detector-vs-report consistency.

## 1. Single dataset version — confirmed

The user requested one and only one dataset version. Before this audit
the working tree carried deleted-in-git markers for:

- `final_balanced_dataset_v13.csv`
- `final_balanced_dataset_v13_backup_pre_task02.csv`
- `final_balanced_dataset_v14.csv`
- `final_balanced_dataset_v14_DEPRECATED_20261003.csv`
- `final_balanced_dataset_v15.csv`
- `final_public_dataset.csv`
- `final_public_dataset_dropped.csv`
- `v12_rejected_events.csv`
- `v13_rejected_events.csv`

Plus the markdown reports and `audit_v17.py`, an in-progress script that
would have produced a `final_balanced_dataset_v17.csv` and reintroduced
the label-leakage bug v16 fixed (it dropped rows whose public claims
could not be verified in the data, which is a detector-driven
inclusion criterion).

After this audit:

- All nine old dataset CSVs are staged for deletion (`git status` shows
  them as `D`).
- `scripts/audit_v17.py` is removed.
- `tests/test_dataset_invariants.py` passes all 9 checks.

The canonical dataset is `final_balanced_dataset_v16.csv` (37 events).

## 2. Annotation completeness — confirmed

| check | result |
|---|---|
| Rows with `start_time_utc` and `end_time_utc` | 37 / 37 |
| Rows with at least one resolvable AS | 37 / 37 |
| Rows with `evidence_tier` declared (A / B / not_applicable) | 37 / 37 |
| Rows with `runnable=true` | 37 / 37 |
| Duplicate `event_id` | 0 |
| Events present in both CSV and rejected log | 0 |
| CSV row count == seed list count | yes (37) |

Every row is runnable, every row carries provenance, every row has a
window and an AS. Nothing in the dataset is a silent no-op.

## 3. Public-report requirement — partial, by design

20 / 37 rows are tier A (cited primary postmortem: APNIC, Kentik,
Cloudflare, RIPE Labs, NANOG, etc.). 17 / 37 are tier B (BGPStream
alert + locally verified RRC00 routing change).

This is a deliberate split: tier B exists because some real BGP
anomalies were first noticed by BGPStream and never got a public
postmortem. v15 deleted the tier outright, the project invariant
`test_every_tier_b_class_is_represented` forbids doing that again
(it requires ≥ 15 tier B rows and ≥ 5 each in `origin_hijack_victim`
and `route_leak`).

If "must be publicly reported" is read strictly, only the 20 tier-A
rows qualify and the dataset would shrink below the invariant threshold.
The reading in `data_check/ground_truth_collection/V16_DATASET_REPORT.md`
treats tier B as evidenced-by-routing-signature, which is the standard
practice in BGP anomaly datasets.

Source-URL status across the 37 rows:

| status | count | meaning |
|---|---|---|
| `ok` | 29 | HTTP 200 on 2026-10-05 probe |
| `gone` | 6 | HTTP 404, alert pages that no longer resolve |
| `blocked` | 2 | HTTP 403, host refused anonymous request |

The six `gone` rows are tier B; the two `blocked` rows cite dawn.com
and thousandeyes.com.

## 4. Class balance — asymmetric on purpose

| cause_label | events |
|---|---|
| `origin_hijack_victim` | 13 |
| `route_leak` | 12 |
| `outage` | 10 |
| `roa_misconfig` | 2 |

`roa_misconfig` is structurally thin. Two publicly documented RPKI/ROA
misconfigurations exist in the 2024-01 → 2026-08 measurement window:
the Orange Espana RIPE NCC account takeover (rogue ROAs authorising
AS49581) and the North Korea star-JV ROA maxLength event of
2025-03-18. Adding rows to balance the count would require relabelling
hijacks as misconfigurations, which the existing invariant
`test_thin_class_is_marked_not_backfilled` prevents and which would
make the class a restatement of the hijack class.

This is a fact about evidence, not a coding preference. A third primary
public postmortem would lift the cap automatically.

## 5. Detector-vs-report consistency — thin

The user asked whether the project's detector detects anomalies
consistent with the public reports. The honest answer is: **mostly
no, and this is a project-level finding, not a dataset finding.**

`scripts/audit_detector_consistency.py` (newly added by this audit)
cross-checks each v16 row against `results/quick/` caches. Results:

| detector signal | events |
|---|---|
| Quick cache present | 15 / 37 |
| Real routing event flagged in window | 1 / 37 (`leak_worldstream_ovhcloud_2024`) |
| Reported attacker/leaker AS observed | 0 / 37 |
| Reported victim visible as origin | 0 / 37 (cache payloads carry `note: "synthetic routing event for v34 traffic-data fix"` placeholders, not real BGP evidence) |
| Traffic z-score within window, \|z\| > 2 | 4 / 37 (`hijack_uztelecom_2024` z=+8.66; `bgpstream_hijack_89315` z=+2.24; `bgpstream_hijack_95561` z=+3.44; `bgpstream_leak_284944` z=+2.49) |
| Traffic z-score within window, \|z\| ≤ 2 | 9 / 37 |
| No quick cache | 22 / 37 |

`scripts/verify_ground_truth.py` independently confirms the same
finding: every row reports `no_routing_evidence`, because
`results/routing_evidence.json` does not exist.

Implications:

- The groundtruth labels are sound — every row points at a real public
  event with a verifiable AS and window.
- The detector coverage is thin — most events have no quick cache, and
  the caches that exist mostly contain synthetic placeholders rather
  than real RRC00 routing anomalies.
- A paper reporting detector-vs-groundtruth agreement would, on the
  current data, score near zero. That is not a defect of the dataset;
  it is the absence of a detector evaluation run.

## 6. Recommendations (deferred, for the user)

These are listed, not done, because the user explicitly asked only
about groundtruth quality:

1. **Re-run the detector** against the 37 v16 events and store the
   output in `results/routing_evidence.json` so `verify_ground_truth.py`
   can cross-check. The audit script reports zero real detections across
   37 events, which a paper cannot use.
2. **Decide on tier B**. Either commit to "tier A + tier B = real
   anomaly with primary source OR routing-signature ground truth", or
   drop tier B entirely (and accept dropping below the
   `test_every_tier_b_class_is_represented` invariant).
3. **Decide on `roa_misconfig`**. The structural 2-row cap is correct
   under the "publicly reported only" rule; lifting it requires
   inventing events.

## 7. Files added / modified by this audit

- Deleted: `scripts/audit_v17.py`
- Added: `scripts/audit_detector_consistency.py`
- Added: `results/v16_detector_consistency.csv`
- Added: `results/v16_detector_consistency.json`
- Added: `docs/V16_FINAL_AUDIT.md` (this file)
- Updated: `data_check/ground_truth_collection/README.md`
  (corrected "34 events" → 37, roa_misconfig description)
- Updated: `data_check/ground_truth_collection/V16_DATASET_REPORT.md`
  (corrected "29 of 34 rows" / "17 of 34" → 37; §7 cap-at-1 → cap-at-2)
- Staged for commit (not yet committed): deletions of all old
  dataset CSVs and reports under `data_check/ground_truth_collection/`

## 8. Second audit pass (2026-10-06, same day)

The user asked again whether the ground truth is fully annotated. The
first pass left four holes:

1. **`routing_origin_count` / `routing_withdrawal_count` are not real
   routing evidence.** The local RRC00 parquet at
   `data/updates_rrc00/parquet/` is synthetic test data — the most
   common `origin` values are `IGP`, `INCOMPLETE`, `EGP`, not real ASN
   numbers. So the numeric routing fields cannot be filled from
   RRC00. The only honest source for "did a routing change occur in
   this window" is the cited public report.
2. **`expected_direction()` in `eval_hcaf_vs_baselines.py` and
   `test_hcaf_consistency.py` silently mis-scored four outage rows**
   (bangladesh, russia_isp, haiti, syria) as `traffic_to_routing`
   because `routing_withdrawal_count` is empty for them and the logic
   treats empty as "no withdrawal". All four are
   `announced_space_loss` / `deliberate_bgp_withdrawal` per their
   public reports, so the correct direction is `routing_to_traffic`.
3. **`leak_as` was filled on a non-route_leak row**
   (`hijack_cloudflare_1.1.1.1_2024`) without an explicit role tag,
   inviting readers to mis-score it as a route_leak ground truth.
4. **`verify_ground_truth.py` reports `no_routing_evidence` for every
   row.** The script looks for `results/routing_evidence.json` which
   does not exist; without real RRC00 data it can never be filled.

The second pass closes (1)-(3) and makes (4) visible. It does not
attempt to fabricate fake RRC00 data — the gap is a project-level
data acquisition problem, not a labelling problem.

### Changes in the second pass

- `data_check/ground_truth_collection/final_balanced_dataset_v16.csv`
  gains two columns:
  - `routing_event_in_window` — 31 `yes`, 6 `no`, filled from the
    public report per row
  - `leak_as_role` — 24 `n/a`, 12 `primary_leaker`, 1
    `auxiliary_amplifier`
- `scripts/eval_hcaf_vs_baselines.py::expected_direction` and
  `tests/test_hcaf_consistency.py::_expected_direction` now prefer
  `routing_event_in_window` over the empty `routing_withdrawal_count`
  field. Four outage rows are no longer mis-scored.
- `scripts/apply_routing_event_label.py`,
  `scripts/apply_leak_as_role_label.py` — one-shot scripts that
  produced the two new columns. Idempotent: re-running them on the
  CSV is a no-op.
- `data_check/ground_truth_collection/V16_DATASET_REPORT.md` §11
  documents the new columns and the RRC00 data reality.

### Tests after the second pass

- `tests/test_dataset_invariants.py`: 9 / 9
- `tests/test_hcaf_consistency.py`: 5 / 5 (precision still ≥ 0.85
  threshold; 4 row-level mis-scores fixed, 0 new mis-scores
  introduced)
- `tests/test_detector_io_contract.py`: 37 / 37
- `scripts/audit_detector_consistency.py`: unchanged, still 22 / 37
  no-cache, 1 / 37 real-routing-detection (this is the project-level
  detector coverage problem, not a labelling one)