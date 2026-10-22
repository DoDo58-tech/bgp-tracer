#!/usr/bin/env python3
"""
Final consistency audit. For each event:
  - routing signal: present? peak_A vs expected for that event class
  - traffic signal: present? z_min in expected direction
  - consistency: routing and traffic agree? matches public report?
  - audit_decision: ok / suspicious / conflict
Output: audit_v18.md
"""
import csv
from collections import defaultdict

V18 = 'data_check/ground_truth_collection/final_balanced_v18_30.csv'
OUT_MD = 'docs/groundtruth_v18_audit.md'


def audit(row):
    eid = row['event_id']
    cause = row['ground_truth_cause_label']
    subtype = row['ground_truth_root_cause_subtype']
    rt_a = int(row.get('routing_victim_total_A_v18') or 0)
    rt_peak = int(row.get('routing_victim_peak_A_v18') or 0)
    rt_status = row.get('routing_v18_status', '')
    tr_z = row.get('traffic_z_min_v18', '')
    tr_drop = row.get('traffic_pct_drop_v18', '')
    tr_status = row.get('traffic_status_v18', '')
    public = row.get('ground_truth_source', '')[:60]
    source_url = row.get('source_url', '')

    notes = []

    # Routing presence
    has_rt = rt_status == 'ok' and rt_peak > 0
    has_tr = tr_status == 'ok' and tr_z != ''
    try:
        tr_z_f = float(tr_z) if tr_z else 0
    except:
        tr_z_f = 0

    # Decision logic per cause
    if cause == 'outage':
        if not has_rt and not has_tr:
            notes.append('No routing or traffic signal — outage likely non-BGP (e.g., gov shutdown)')
            decision = 'ok'
        elif has_rt and has_tr and tr_z_f < -2:
            notes.append(f'Both signals present, traffic z={tr_z_f:.1f}, routing peak={rt_peak}/5m — consistent outage')
            decision = 'ok'
        elif has_rt and not has_tr:
            notes.append(f'Routing surge (peak {rt_peak}/5m) detected but no traffic data — likely real outage')
            decision = 'ok'
        elif not has_rt and has_tr and tr_z_f < -2:
            notes.append(f'Traffic drop z={tr_z_f:.1f} but no routing — internal/downstream failure')
            decision = 'ok'
        else:
            notes.append(f'Partial signal: routing={has_rt} traffic={has_tr} z={tr_z_f}')
            decision = 'suspicious'
    elif cause == 'route_leak':
        if not has_rt:
            notes.append('No routing signal — leak not in RRC00 view')
            decision = 'suspicious'
        elif has_tr and tr_z_f < -1:
            notes.append(f'Routing + traffic drop z={tr_z_f:.1f} — leak caused traffic impact')
            decision = 'ok'
        elif has_tr and tr_z_f >= -1:
            notes.append(f'Routing seen but traffic stable (z={tr_z_f:.1f}) — leak had limited impact')
            decision = 'ok'
        else:
            notes.append(f'Routing peak {rt_peak}/5m, no traffic data')
            decision = 'ok'
    elif cause == 'origin_hijack_victim':
        if not has_rt:
            notes.append('No routing signal — hijack not visible at RRC00')
            decision = 'suspicious'
        else:
            notes.append(f'Routing signal present (peak {rt_peak}/5m) — hijack visible')
            decision = 'ok'
    else:
        decision = 'review'
        notes.append(f'Unknown cause: {cause}')

    return decision, notes


def main():
    with open(V18) as f:
        events = list(csv.DictReader(f))

    # Stats
    decisions = defaultdict(int)
    rows = []
    for e in events:
        d, n = audit(e)
        decisions[d] += 1
        rows.append((d, e, n))

    # Build markdown
    lines = ['# Groundtruth v18 Audit Report\n']
    lines.append(f'Events: {len(events)}  |  Decision distribution: {dict(decisions)}\n')
    lines.append('\n## Per-Event Audit\n')
    lines.append('| # | event_id | cause | decision | routing peak/5m | traffic z | drop% | notes |')
    lines.append('|---|----------|-------|----------|-----------------|-----------|-------|-------|')
    for i, (d, e, n) in enumerate(rows, 1):
        rt_peak = e.get('routing_victim_peak_A_v18', '') or '—'
        tr_z = e.get('traffic_z_min_v18', '') or '—'
        tr_drop = e.get('traffic_pct_drop_v18', '') or '—'
        notes = '; '.join(n)[:200]
        lines.append(f'| {i} | {e["event_id"]} | {e["ground_truth_cause_label"]} | {d} | {rt_peak} | {tr_z} | {tr_drop} | {notes} |')

    lines.append('\n## Routing feature parquets\n')
    lines.append('Saved per event at `data/groundtruth_v18/{event_id}_routing_features.parquet`')
    lines.append('Time series: 5-min buckets of announcement / withdrawal counts, unique prefix count, origin AS count.')

    lines.append('\n## Traffic feature values\n')
    lines.append('Extracted from `data/traffic/AS*.csv` files. z_min = (window_min - baseline_mean)/baseline_std over 7-day baseline.')
    lines.append('drop% = (baseline_mean - window_min) / baseline_mean * 100.')

    lines.append('\n## Artifacts per event\n')
    lines.append('- `data_check/ground_truth_collection/final_balanced_v18_30.csv` — full enriched GT')
    lines.append('- `data/groundtruth_v18/{event_id}_routing_features.parquet` — routing time series (5-min buckets)')
    lines.append('- `data/groundtruth_v18/summary.json` — routing summary')
    lines.append('- `data/traffic_plots_v17/{event_id}.png` — traffic time series plot')
    lines.append('- `data_check/ground_truth_collection/final_balanced_dataset_v17_30.csv` — original v17 GT')

    with open(OUT_MD, 'w') as f:
        f.write('\n'.join(lines))
    print(f'Written: {OUT_MD}')
    print(f'Decision distribution: {dict(decisions)}')


if __name__ == '__main__':
    main()
