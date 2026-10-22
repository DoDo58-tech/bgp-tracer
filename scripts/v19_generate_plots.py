#!/usr/bin/env python3
"""
Generate traffic PNG plots for v19 events.
- If traffic data exists: use plot_traffic_comparison_beautiful
- If no traffic data: generate routing-only plot (BGP announcement surge)
"""
import os
import sys
import csv
import json
import polars as pl
import numpy as np
from pathlib import Path
from datetime import datetime, timedelta

# Add path
sys.path.insert(0, '.')
from detectors.traffic.traffic_plotting import plot_traffic_comparison_beautiful

GT = 'data_check/ground_truth_collection/final_balanced_v19_40.csv'
V19_DIR = Path('data/groundtruth_v19')
V18_DIR = Path('data/groundtruth_v18')
PLOT_DIR = Path('data/traffic_plots_v19')
PLOT_DIR.mkdir(parents=True, exist_ok=True)
TRAFFIC_DIR = Path('data/traffic')


def find_traffic_file(asn, date):
    import glob
    pattern = str(TRAFFIC_DIR / f'AS{asn}_traffic_*T*_to_*T*.csv')
    files = glob.glob(pattern)
    target = datetime.fromisoformat(date + 'T00:00:00')
    candidates = []
    for f in files:
        base = os.path.basename(f)
        try:
            parts = base.replace('.csv', '').split('_to_')
            start_str = parts[0].split('_traffic_')[1]
            end_str = parts[1]
            s = datetime.fromisoformat(start_str.rstrip('Z'))
            e = datetime.fromisoformat(end_str.rstrip('Z'))
            if s <= target + timedelta(days=1) and e >= target:
                candidates.append((f, s, e))
        except Exception:
            continue
    if not candidates:
        return None
    candidates.sort(key=lambda x: (x[2] - x[1]))
    return candidates[0][0]


def plot_traffic_for_event(e):
    """Generate traffic comparison plot (matches reference format)."""
    asn = e['victim_as'].replace('AS', '')
    date = e['date']
    s = e['start_utc']
    en = e['end_utc']
    f = find_traffic_file(asn, date)
    if not f:
        return None
    df = pl.read_csv(f, try_parse_dates=True)
    if df['timestamp'].dtype == pl.Utf8:
        df = df.with_columns(pl.col('timestamp').str.to_datetime('%Y-%m-%dT%H:%M:%S', strict=False))
    if hasattr(df['timestamp'].dtype, 'time_zone') and df['timestamp'].dtype.time_zone is not None:
        df = df.with_columns(pl.col('timestamp').dt.replace_time_zone(None))
    # Use 24h window around event
    start_dt = datetime.fromisoformat(s.replace(' ', 'T').replace('Z', ''))
    end_dt = datetime.fromisoformat(en.replace(' ', 'T').replace('Z', ''))
    # 1 day before and 1 day after for context
    ext_start = (start_dt - timedelta(hours=2)).strftime('%Y-%m-%d %H:%M')
    ext_end = (end_dt + timedelta(hours=2)).strftime('%Y-%m-%d %H:%M')
    df_w = df.filter((pl.col('timestamp') >= datetime.fromisoformat(ext_start)) & (pl.col('timestamp') <= datetime.fromisoformat(ext_end)))
    if len(df_w) < 5:
        return None
    timestamps = df_w['timestamp'].to_list()
    values = df_w['value'].to_list()
    # Historical data: 7 days before
    hist_data = []
    for d in [7, 14, 21]:
        hist_start = (start_dt - timedelta(days=d)).strftime('%Y-%m-%d %H:%M')
        hist_end = (start_dt - timedelta(days=d-1)).strftime('%Y-%m-%d %H:%M')
        try:
            df_h = df.filter((pl.col('timestamp') >= datetime.fromisoformat(hist_start)) & (pl.col('timestamp') <= datetime.fromisoformat(hist_end)))
            if len(df_h) > 0:
                hist_data.append({
                    'daily_ago': d,
                    'values': df_h['value'].to_list(),
                })
        except Exception:
            continue
    out_path = plot_traffic_comparison_beautiful(
        asn=asn,
        start_date=ext_start,
        end_date=ext_end,
        timestamps=timestamps,
        current_values=values,
        historical_data=hist_data,
        historical_means=[],
        historical_stds=[],
        anomalies=None,
        overlay_series=None,
        event_name=e['event_id'],
        output_dir=str(PLOT_DIR),
        title_suffix=f" - {e['event_id']} ({e['cause']})",
    )
    return out_path


def plot_routing_surge(e):
    """For events with no traffic data, plot the routing spike as a chart."""
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    eid = e['event_id']
    # Find routing features
    for d in [V19_DIR, V18_DIR]:
        rp = d / f'{eid}_routing_features.parquet'
        if rp.exists():
            df = pl.read_parquet(rp)
            break
    else:
        return None
    if len(df) == 0:
        return None
    # bucket column = timestamp
    if 'bucket' in df.columns:
        ts_col = 'bucket'
    else:
        ts_col = df.columns[0]
    df = df.with_columns(pl.col(ts_col).alias('ts'))
    if df['ts'].dtype == pl.Datetime:
        df = df.with_columns(pl.col('ts').dt.replace_time_zone(None))
    fig, ax = plt.subplots(figsize=(18, 8))
    ax.plot(df['ts'], df['announcement_count'], color='#2E86AB', linewidth=2.5, marker='o', markersize=4, label='Announcements / 5min')
    if 'withdrawal_count' in df.columns:
        ax.plot(df['ts'], df['withdrawal_count'], color='#E74C3C', linewidth=1.5, label='Withdrawals / 5min', alpha=0.6)
    if 'unique_prefix_count' in df.columns:
        ax.plot(df['ts'], df['unique_prefix_count'], color='#6A5ACD', linewidth=1.5, label='Unique Prefixes', alpha=0.6)
    # Highlight event window
    if 'start_utc' in e and 'end_utc' in e:
        s = datetime.fromisoformat(e['start_utc'].replace(' ', 'T').replace('Z', ''))
        en = datetime.fromisoformat(e['end_utc'].replace(' ', 'T').replace('Z', ''))
        import matplotlib.dates as mdates
        ax.axvspan(mdates.date2num(s), mdates.date2num(en), alpha=0.15, color='#FDE68A', label='Analysis Period')
    ax.set_title(f'{eid} - {e["cause"]} - {e.get("subtype", "")} - Routing Activity', fontsize=16, fontweight='bold')
    ax.set_xlabel('Time (UTC)')
    ax.set_ylabel('Count / 5min bucket')
    ax.legend()
    ax.grid(alpha=0.3)
    fig.autofmt_xdate()
    out = PLOT_DIR / f'{eid}_routing_surge.png'
    plt.tight_layout()
    plt.savefig(out, dpi=150, bbox_inches='tight')
    plt.close()
    return str(out)


def main():
    events = list(csv.DictReader(open(GT)))
    print(f'Generating plots for {len(events)} events...')
    ok = 0
    for e in events:
        eid = e['event_id']
        # Prefer existing v17 traffic plot
        existing = Path('data/traffic_plots_v17') / f'{eid}.png'
        if existing.exists():
            print(f'  {eid:<55} -> {existing.name} (existing)')
            ok += 1
            continue
        # Else use routing surge
        out = plot_routing_surge(e)
        if out:
            ok += 1
            print(f'  {eid:<55} -> {os.path.basename(out)}')
        else:
            print(f'  {eid:<55} NO PLOT')
    print(f'\nGenerated {ok}/{len(events)} plots in {PLOT_DIR}')


if __name__ == '__main__':
    main()
