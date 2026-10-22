#!/usr/bin/env python3
"""
Build v19 final audit + rejected set + per-event evidence summary.
"""
import json
import csv
import os
from pathlib import Path
from collections import defaultdict, Counter

V18_CSV = 'data_check/ground_truth_collection/final_balanced_v18_30.csv'
REJ_CSV = 'data_check/ground_truth_collection/final_balanced_dataset_v17_rejected.csv'
V19_CSV = 'data_check/ground_truth_collection/final_balanced_v19_40.csv'
OUT_DIR = Path('data/groundtruth_v19')
GT_V18 = Path('data/groundtruth_v18')


def load_csv(p):
    with open(p) as f:
        return list(csv.DictReader(f))


def build_event_evidence():
    """For every event in v19 + v18 + rejected, list all available artifacts."""
    v19 = load_csv(V19_CSV)
    v18 = load_csv(V18_CSV)
    rej = load_csv(REJ_CSV)
    out = []
    for e in v19:
        eid = e['event_id']
        # Routing feature in v19 or v18 dir
        v19_parq = OUT_DIR / f'{eid}_routing_features.parquet'
        v18_parq = GT_V18 / f'{eid}_routing_features.parquet'
        routing_src = v19_parq if v19_parq.exists() else (v18_parq if v18_parq.exists() else None)
        # Traffic ts
        tr_parq_v19 = list(OUT_DIR.glob(f'*_{e["date"].replace("-","")}_traffic_ts.parquet'))
        tr_parq_v18 = list(GT_V18.glob(f'{eid}_traffic_timeseries.parquet'))
        traffic_src = tr_parq_v19[0] if tr_parq_v19 else (tr_parq_v18[0] if tr_parq_v18 else None)
        # Plot
        plot = Path(f'data/traffic_plots_v17/{eid}.png')
        evidence = {
            'event_id': eid,
            'cause': e['cause'],
            'subtype': e['subtype'],
            'date': e['date'],
            'routing_feature_parquet': str(routing_src) if routing_src else '',
            'traffic_ts_parquet': str(traffic_src) if traffic_src else '',
            'traffic_png': str(plot) if plot.exists() else '',
            'public_source': e.get('source', ''),
            'source_url': e.get('source_url', ''),
            'evidence_tier': e.get('evidence_tier', ''),
        }
        out.append(evidence)
    return out


def audit_decision(e, v18_or_v19):
    """Same logic as v18 audit."""
    cause = e['cause']
    rt_peak = int(e.get('routing_peak_A') or 0)
    rt_status = e.get('routing_status', '')
    tr_z_str = e.get('traffic_z_min', '')
    has_rt = rt_status == 'ok' and rt_peak > 0
    has_tr = tr_z_str not in ('', 'n/a')
    try:
        tr_z = float(tr_z_str) if has_tr else 0
    except:
        tr_z = 0

    if cause == 'outage':
        if not has_rt and not has_tr:
            return 'ok', 'no_signal_non_bgp'
        if has_rt and has_tr and tr_z < -2:
            return 'ok', 'both_signals_strong'
        if has_rt and not has_tr:
            return 'ok', 'routing_only'
        if not has_rt and has_tr and tr_z < -2:
            return 'ok', 'traffic_only'
        return 'suspicious', f'partial rt={has_rt} tr={has_tr} z={tr_z}'
    elif cause == 'route_leak':
        if not has_rt:
            return 'suspicious', 'no_routing_signal'
        if has_tr and tr_z < -1:
            return 'ok', 'both_signals'
        return 'ok', 'routing_only'
    elif cause == 'origin_hijack_victim':
        if not has_rt:
            return 'suspicious', 'no_routing_signal'
        return 'ok', 'routing_only'
    return 'review', 'unknown_cause'


def main():
    # Build evidence for v19
    evidences = build_event_evidence()
    v19 = load_csv(V19_CSV)
    v19_by_id = {e['event_id']: e for e in v19}

    decisions = []
    for ev in evidences:
        e = v19_by_id[ev['event_id']]
        d, note = audit_decision(e, 'v19')
        ev['audit_decision'] = d
        ev['audit_note'] = note
        decisions.append(d)

    # Stats
    decision_counts = Counter(decisions)
    print(f'v19 audit: {len(evidences)} events, decisions: {dict(decision_counts)}')

    # Save evidence list as JSON
    with open(OUT_DIR / 'event_evidence.json', 'w') as f:
        json.dump(evidences, f, indent=2, default=str)

    # Build markdown audit report
    lines = ['# Groundtruth v19 Audit Report\n']
    lines.append(f'Events: {len(evidences)}  |  Decisions: {dict(decision_counts)}')
    lines.append(f'Outage: {sum(1 for e in evidences if e["cause"]=="outage")}')
    lines.append(f'Route leak: {sum(1 for e in evidences if e["cause"]=="route_leak")}')
    lines.append(f'Origin hijack (victim): {sum(1 for e in evidences if e["cause"]=="origin_hijack_victim")}')
    lines.append('')
    lines.append('## Per-Event Audit Table\n')
    lines.append('| # | event_id | cause | decision | routing peak | traffic z | drop% | evidence complete |')
    lines.append('|---|----------|-------|----------|--------------|-----------|-------|-------------------|')
    for i, ev in enumerate(evidences, 1):
        e = v19_by_id[ev['event_id']]
        rt_peak = e.get('routing_peak_A', '')
        tr_z = e.get('traffic_z_min', '') or '—'
        tr_drop = e.get('traffic_pct_drop', '') or '—'
        has_rt = bool(ev['routing_feature_parquet'])
        has_tr = bool(ev['traffic_ts_parquet'])
        has_png = bool(ev['traffic_png'])
        ev_complete = '✅' if (has_rt and (has_tr or has_png)) else '⚠️'
        lines.append(f'| {i} | {ev["event_id"]} | {ev["cause"]} | {ev["audit_decision"]} | {rt_peak} | {tr_z} | {tr_drop} | {ev_complete} |')

    # Rejected set
    lines.append('\n## v17 Rejected Events (with routing/traffic evidence extracted)\n')
    lines.append('| event_id | cause | rejection reason | routing peak A | routing total A | routing parquet |')
    lines.append('|----------|-------|------------------|----------------|------------------|-----------------|')
    rej_data = json.load(open(OUT_DIR / 'rejected/rejected_with_evidence.json'))
    for r in rej_data:
        rp = r.get('routing_parquet', '—')
        lines.append(f'| {r["event_id"]} | {r["cause"]} | {r["rejection_reason"]} | {r.get("routing_peak_A", 0)} | {r.get("routing_total_A", 0)} | {rp} |')

    lines.append('\n### Rejection details\n')
    rej_csv = load_csv(REJ_CSV)
    for r in rej_csv:
        lines.append(f'- **{r["event_id"]}** ({r["ground_truth_cause_label"]}): {r.get("rejection_reason", "")}')
        lines.append(f'  - Source: {r.get("ground_truth_source", "")}')
        lines.append(f'  - URL: {r.get("source_url", "")}')

    # Artifacts
    lines.append('\n## Artifacts\n')
    lines.append('- `data_check/ground_truth_collection/final_balanced_v19_40.csv` — final v19 GT (40 events target, currently 39)')
    lines.append('- `data/groundtruth_v18/` — routing features for v18 events (parquet)')
    lines.append('- `data/groundtruth_v19/` — routing + traffic features for new v19 candidates')
    lines.append('- `data/groundtruth_v19/candidate_metadata.jsonl` — metadata for all v19 candidates')
    lines.append('- `data/groundtruth_v19/event_evidence.json` — per-event artifact inventory')
    lines.append('- `data/traffic_plots_v17/` — traffic PNG plots')

    with open('docs/groundtruth_v19_audit.md', 'w') as f:
        f.write('\n'.join(lines))
    print(f'Audit report: docs/groundtruth_v19_audit.md')

    # Save per-event artifacts list
    with open(OUT_DIR / 'per_event_artifact_inventory.csv', 'w', newline='') as f:
        keys = list(evidences[0].keys())
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(evidences)
    print(f'Artifact inventory: {OUT_DIR}/per_event_artifact_inventory.csv')


if __name__ == '__main__':
    main()
