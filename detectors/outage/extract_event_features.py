import os
import logging
import re
import csv
import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Set, Tuple, Optional
import pandas as pd
from ipaddress import ip_network

# Data directory: bgp_tracer/data/ instead of detectors/outage/data/
DATA_DIR = Path(__file__).parent.parent.parent / "data"
CSV_FILE = DATA_DIR / "traffic-outage-info.csv"
UPDATES_DIR = DATA_DIR / "updates_rrc00" / "decoded"
OUTPUT_DIR = DATA_DIR / "event_features"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Log directory: bgp_tracer/logs/
import sys as _sys
_sys.path.append(str(Path(__file__).parent.parent.parent))
from config import LOG_FILE

# Avoid duplicate logging setup
_root = logging.getLogger()
if not _root.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(processName)s %(message)s',
        handlers=[
            logging.FileHandler(LOG_FILE, encoding='utf-8'),
            logging.StreamHandler()
        ]
    )
else:
    _module_logger = logging.getLogger(__name__)
    _module_logger.addHandler(logging.FileHandler(LOG_FILE, encoding='utf-8'))

logger = logging.getLogger(__name__)

# Analysis parameters
# Event window: [event_start, event_end]
# Baseline window: [event_start - BASELINE_DAYS, event_start)
BASELINE_DAYS = 7
Z_SCORE_THRESHOLD = 3.0
BUCKET_MINUTES = 5
MAX_WORKERS = 32
USE_PROCESSES = True


def parse_as_list(as_string):
    if pd.isna(as_string) or not as_string or as_string.strip() == '':
        return set()
    
    as_set = set()
    parts = re.split(r'[,\s、]+', str(as_string))
    for part in parts:
        part = part.strip()
        if not part:
            continue
        part = re.sub(r'^AS', '', part, flags=re.IGNORECASE)
        try:
            as_num = int(part)
            as_set.add(as_num)
        except ValueError:
            numbers = re.findall(r'\d+', part)
            for num_str in numbers:
                try:
                    as_set.add(int(num_str))
                except ValueError:
                    continue
    return as_set


def parse_datetime(dt_string):
    if pd.isna(dt_string):
        raise ValueError("Empty datetime string")
    
    dt_string = str(dt_string).strip()
    
    formats = [
        "%Y/%m/%d %H:%M",
        "%Y-%m-%d %H:%M",
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(dt_string, fmt)
        except ValueError:
            continue
    
    try:
        return pd.to_datetime(dt_string).to_pydatetime()
    except Exception as e:
        raise ValueError(f"cannot parse datetime: {dt_string}, error: {e}")


def find_update_files(time_start, time_end):
    files = []
    
    current = time_start
    while current <= time_end:
        minute = (current.minute // BUCKET_MINUTES) * BUCKET_MINUTES
        rounded_time = current.replace(minute=minute, second=0, microsecond=0)
        
        filename = f"updates.{rounded_time.strftime('%Y%m%d.%H%M')}.txt"
        filepath = UPDATES_DIR / filename
        
        if filepath.exists():
            files.append(filepath)
        
        current += timedelta(minutes=BUCKET_MINUTES)
    
    return sorted(files)


def parse_bgp_line(line):
    if not line.strip() or not line.startswith('BGP4MP'):
        return None
    
    parts = line.strip().split('|')
    if len(parts) < 6:
        return None
    
    try:
        msg_type = parts[2]  # A/W
        peer_as = int(parts[4]) if parts[4].strip() else None
        prefix = parts[5] if len(parts) > 5 and parts[5].strip() else None
        as_path = parts[6] if len(parts) > 6 and parts[6].strip() else ""
        
        timestamp_str = parts[1]
        try:
            timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            try:
                timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M')
            except ValueError:
                return None
        
        return {
            'timestamp': timestamp,
            'type': msg_type,
            'peer_as': peer_as,
            'prefix': prefix,
            'as_path': as_path,
        }
    except (ValueError, IndexError):
        return None


def extract_as_from_path(as_path):
    if not as_path or pd.isna(as_path):
        return set()
    
    as_set = set()
    as_path_clean = re.sub(r'\{[^}]+\}', '', as_path)
    
    for part in as_path_clean.split():
        part = part.strip()
        if not part:
            continue
        try:
            as_num = int(part)
            as_set.add(as_num)
        except ValueError:
            continue
    
    return as_set


def extract_features_for_as(update_files, target_as_set):
    features = {
        'announcement_count': 0,
        'withdrawal_count': 0,
        'announced_prefixes': set(),
        'withdrawn_prefixes': set(),
        'unique_prefixes': set(),
        'peer_as_count': defaultdict(int),
        'prefix_announce_count': defaultdict(int),
        'prefix_withdraw_count': defaultdict(int),
        'avg_path_length': [],
        'origin_as_changes': defaultdict(set),
        'flapping_prefixes': set(),
        'total_messages': 0,
    }
    
    prefix_history = defaultdict(list)  # per-prefix state changes
    
    for filepath in update_files:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    bgp_msg = parse_bgp_line(line)
                    if not bgp_msg:
                        continue
                    
                    # Check relevance to target AS set
                    is_relevant = False
                    
                    # 1) peer AS is in target set
                    if bgp_msg['peer_as'] in target_as_set:
                        is_relevant = True
                    
                    # 2) AS path contains any target AS
                    if bgp_msg['as_path']:
                        path_as_set = extract_as_from_path(bgp_msg['as_path'])
                        if path_as_set & target_as_set:
                            is_relevant = True
                        
                        # record AS path length sample
                        if is_relevant:
                            features['avg_path_length'].append(len(path_as_set))
                    
                    if not is_relevant:
                        continue
                    
                    prefix = bgp_msg['prefix']
                    if not prefix:
                        continue
                    
                    features['total_messages'] += 1
                    
                    # count peer AS
                    if bgp_msg['peer_as']:
                        features['peer_as_count'][bgp_msg['peer_as']] += 1
                    
                    # record prefix history
                    prefix_history[prefix].append({
                        'timestamp': bgp_msg['timestamp'],
                        'type': bgp_msg['type'],
                    })
                    
                    if bgp_msg['type'] == 'A':  # announcement
                        features['announcement_count'] += 1
                        features['announced_prefixes'].add(prefix)
                        features['unique_prefixes'].add(prefix)
                        features['prefix_announce_count'][prefix] += 1
                        
                        # origin AS = last AS in path
                        if bgp_msg['as_path']:
                            path_as_list = list(extract_as_from_path(bgp_msg['as_path']))
                            if path_as_list:
                                origin_as = path_as_list[-1]
                                features['origin_as_changes'][prefix].add(origin_as)
                    
                    elif bgp_msg['type'] == 'W':  # withdrawal
                        features['withdrawal_count'] += 1
                        features['withdrawn_prefixes'].add(prefix)
                        features['unique_prefixes'].add(prefix)
                        features['prefix_withdraw_count'][prefix] += 1
                        
        except Exception as e:
            print(f"Warning: failed to process file {filepath}: {e}")
            continue
    
    # Mark route flapping when both A and W exist for the same prefix
    for prefix, history in prefix_history.items():
        has_announce = any(h['type'] == 'A' for h in history)
        has_withdraw = any(h['type'] == 'W' for h in history)
        if has_announce and has_withdraw:
            features['flapping_prefixes'].add(prefix)
    
    # Build serializable result
    result = {
        'announcement_count': features['announcement_count'],
        'withdrawal_count': features['withdrawal_count'],
        'announced_prefix_count': len(features['announced_prefixes']),
        'withdrawn_prefix_count': len(features['withdrawn_prefixes']),
        'unique_prefix_count': len(features['unique_prefixes']),
        'unique_peer_as_count': len(features['peer_as_count']),
        'flapping_prefix_count': len(features['flapping_prefixes']),
        'total_messages': features['total_messages'],
        'avg_path_length': sum(features['avg_path_length']) / len(features['avg_path_length']) if features['avg_path_length'] else 0,
        'max_path_length': max(features['avg_path_length']) if features['avg_path_length'] else 0,
        'min_path_length': min(features['avg_path_length']) if features['avg_path_length'] else 0,
        'prefix_announce_count_stats': {
            'max': max(features['prefix_announce_count'].values()) if features['prefix_announce_count'] else 0,
            'avg': sum(features['prefix_announce_count'].values()) / len(features['prefix_announce_count']) if features['prefix_announce_count'] else 0,
        },
        'prefix_withdraw_count_stats': {
            'max': max(features['prefix_withdraw_count'].values()) if features['prefix_withdraw_count'] else 0,
            'avg': sum(features['prefix_withdraw_count'].values()) / len(features['prefix_withdraw_count']) if features['prefix_withdraw_count'] else 0,
        },
        'origin_as_diversity': {prefix: len(as_set) for prefix, as_set in features['origin_as_changes'].items()},
        'top_peer_as': dict(sorted(features['peer_as_count'].items(), key=lambda x: x[1], reverse=True)[:10]),
    }
    
    return result


def bucket_start(ts):
    minute = (ts.minute // BUCKET_MINUTES) * BUCKET_MINUTES
    return ts.replace(minute=minute, second=0, microsecond=0)


def merge_bucket_feature(dst, src):
    dst['announcement_count'] = dst.get('announcement_count', 0) + src.get('announcement_count', 0)
    dst['withdrawal_count'] = dst.get('withdrawal_count', 0) + src.get('withdrawal_count', 0)
    dst['total_messages'] = dst.get('total_messages', 0) + src.get('total_messages', 0)
    dst['announced_prefixes'] = dst.get('announced_prefixes', set()) | src.get('announced_prefixes', set())
    dst['withdrawn_prefixes'] = dst.get('withdrawn_prefixes', set()) | src.get('withdrawn_prefixes', set())
    dst['unique_prefixes'] = dst.get('unique_prefixes', set()) | src.get('unique_prefixes', set())
    dst['flapping_prefixes'] = dst.get('flapping_prefixes', set()) | src.get('flapping_prefixes', set())
    # path length samples
    if 'avg_path_length_samples' not in dst:
        dst['avg_path_length_samples'] = []
    dst['avg_path_length_samples'].extend(src.get('avg_path_length_samples', []))


def finalize_bucket_feature(b):
    # Calculate entropy for edit distances
    def entropy(values):
        if not values:
            return 0.0
        from collections import Counter
        import math
        counts = Counter(values)
        total = len(values)
        return -sum((count/total) * math.log2(count/total) for count in counts.values() if count > 0)
    
    edit_dists = b.get('edit_distances', [])
    intervals = b.get('arrival_intervals', [])
    path_lengths = b.get('path_lengths', [])
    
    return {
        'announcement_count': b.get('announcement_count', 0),
        'withdrawal_count': b.get('withdrawal_count', 0),
        'flapping_prefix_count': len(b.get('flapping_prefixes', set())),
        
        # Route hijacking/leakage core features
        'ori_change_rate': b.get('num_ori_change', 0) / b.get('announcement_count', 1),
        'num_ori_change': b.get('num_ori_change', 0),
        'path_change_rate': (b.get('num_longer', 0) + b.get('num_shorter', 0)) / b.get('announcement_count', 1),
        
        # BGP storm/abnormal behavior features
        'dup_A_rate': b.get('num_dup_A', 0) / b.get('announcement_count', 1),
        'avg_arrival_interval': (sum(intervals) / len(intervals)) if intervals else 0,
        
        # Path diversity features
        'editDis_entropy': entropy(edit_dists),
        'unique_as_count': len(b.get('unique_as_set', set())),
        
        # Peer AS features
        'unique_peer_as_count': len(b.get('peer_as_set', set())),
        
        # Path length features
        'avg_path_length': sum(path_lengths) / len(path_lengths) if path_lengths else 0,
        'max_path_length': max(path_lengths) if path_lengths else 0,
        'min_path_length': min(path_lengths) if path_lengths else 0,
        
        'origin_change_count': b.get('num_ori_change', 0),
    }


def aggregate_timeseries_to_totals(timeseries):
    if not timeseries:
        return {}
    
    total_announcement = 0
    total_withdrawal = 0
    total_messages = 0
    announced_prefixes = 0
    withdrawn_prefixes = 0
    unique_prefixes = 0
    flapping_prefixes = 0
    path_lengths = []
    peer_as_sets = []
    
    for bucket in timeseries.values():
        total_announcement += bucket.get('announcement_count', 0)
        total_withdrawal += bucket.get('withdrawal_count', 0)
        total_messages += bucket.get('total_messages', 0)
        announced_prefixes += bucket.get('announced_prefix_count', 0)
        withdrawn_prefixes += bucket.get('withdrawn_prefix_count', 0)
        unique_prefixes += bucket.get('unique_prefix_count', 0)
        flapping_prefixes += bucket.get('flapping_prefix_count', 0)
        if bucket.get('avg_path_length', 0) > 0:
            path_lengths.append(bucket['avg_path_length'])
        if 'peer_as_set' in bucket:
            peer_as_sets.append(bucket['peer_as_set'])
    
    # Calculate total unique peer AS count
    total_peer_as = set()
    for ps in peer_as_sets:
        total_peer_as.update(ps)
    
    return {
        'announcement_count': total_announcement,
        'withdrawal_count': total_withdrawal,
        'total_messages': total_messages,
        'announced_prefix_count': announced_prefixes,
        'withdrawn_prefix_count': withdrawn_prefixes,
        'unique_prefix_count': unique_prefixes,
        'flapping_prefix_count': flapping_prefixes,
        'avg_path_length': sum(path_lengths) / len(path_lengths) if path_lengths else 0,
        'max_path_length': max(path_lengths) if path_lengths else 0,
        'min_path_length': min(path_lengths) if path_lengths else 0,
        'unique_peer_as_count': len(total_peer_as),
    }


def process_single_file_timeseries(file_path, target_as_list):
    target_as_set = set(target_as_list)
    buckets = {}
    # keep per-prefix state within this file for flapping
    prefix_history = defaultdict(list)
    # Track per-prefix routing state for new features
    prefix_routes = defaultdict(lambda: {'last_as_path': None, 'last_origin': None, 'announce_count': 0, 'withdraw_count': 0, 'had_withdraw': False})
    line_count = 0
    relevant_count = 0
    start_t = time.time()
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore', buffering=1024*1024) as f:
            for line in f:
                line_count += 1
                bgp_msg = parse_bgp_line(line)
                if not bgp_msg or not bgp_msg.get('prefix'):
                    continue
                # relevance
                relevant = False
                if bgp_msg.get('peer_as') in target_as_set:
                    relevant = True
                if bgp_msg.get('as_path'):
                    as_set = extract_as_from_path(bgp_msg['as_path'])
                    if as_set & target_as_set:
                        relevant = True
                if not relevant:
                    continue
                relevant_count += 1

                bucket = bucket_start(bgp_msg['timestamp'])
                b = buckets.get(bucket)
                if b is None:
                    b = {
                        'announcement_count': 0,
                        'withdrawal_count': 0,
                        'total_messages': 0,
                        'announced_prefixes': set(),
                        'withdrawn_prefixes': set(),
                        'unique_prefixes': set(),
                        'avg_path_length_samples': [],
                        'flapping_prefixes': set(),
                        'num_ori_change': 0,
                        'num_longer': 0,
                        'num_shorter': 0,
                        'num_new_A_afterW': 0,
                        'num_dup_A': 0,
                        'num_dup_W': 0,
                        'unique_as_set': set(),
                        'peer_as_set': set(),
                        'path_lengths': [],
                        'prefix_announce_counts': defaultdict(int),
                        'prefix_withdraw_counts': defaultdict(int),
                        'edit_distances': [],
                        'arrival_intervals': [],
                        'last_timestamp': None,
                    }
                    buckets[bucket] = b

                b['total_messages'] += 1
                prefix = bgp_msg['prefix']
                prefix_history[prefix].append(bgp_msg['type'])
                
                if b['last_timestamp'] is not None:
                    interval = (bgp_msg['timestamp'] - b['last_timestamp']).total_seconds()
                    b['arrival_intervals'].append(interval)
                b['last_timestamp'] = bgp_msg['timestamp']
                
                if bgp_msg['type'] == 'A':
                    b['announcement_count'] += 1
                    b['announced_prefixes'].add(prefix)
                    b['unique_prefixes'].add(prefix)
                    b['prefix_announce_counts'][prefix] += 1
                    
                    if bgp_msg.get('as_path'):
                        as_list = list(extract_as_from_path(bgp_msg['as_path']))
                        path_len = len(as_list)
                        b['avg_path_length_samples'].append(path_len)
                        b['path_lengths'].append(path_len)
                        
                        b['unique_as_set'].update(as_list)
                        
                        if bgp_msg.get('peer_as'):
                            b['peer_as_set'].add(bgp_msg['peer_as'])
                        
                        origin_as = as_list[-1] if as_list else None
                        
                        route_state = prefix_routes[prefix]
                        
                        if route_state['had_withdraw']:
                            b['num_new_A_afterW'] += 1
                            route_state['had_withdraw'] = False
                        
                        if route_state['last_as_path'] == bgp_msg['as_path']:
                            b['num_dup_A'] += 1
                        
                        if route_state['last_origin'] is not None and origin_as != route_state['last_origin']:
                            b['num_ori_change'] += 1
                        
                        if route_state['last_as_path'] is not None:
                            old_len = len(route_state['last_as_path'].split())
                            if path_len > old_len:
                                b['num_longer'] += 1
                            elif path_len < old_len:
                                b['num_shorter'] += 1
                            
                            import editdistance
                            old_path_list = route_state['last_as_path'].split()
                            edit_dist = editdistance.eval(old_path_list, [str(a) for a in as_list])
                            b['edit_distances'].append(edit_dist)
                        
                        route_state['last_as_path'] = bgp_msg['as_path']
                        route_state['last_origin'] = origin_as
                        route_state['announce_count'] += 1
                        
                elif bgp_msg['type'] == 'W':
                    b['withdrawal_count'] += 1
                    b['withdrawn_prefixes'].add(prefix)
                    b['unique_prefixes'].add(prefix)
                    b['prefix_withdraw_counts'][prefix] += 1
                    
                    route_state = prefix_routes[prefix]
                    if route_state['withdraw_count'] > 0 and route_state['last_as_path'] is None:
                        b['num_dup_W'] += 1
                    
                    route_state['had_withdraw'] = True
                    route_state['withdraw_count'] += 1
                    route_state['last_as_path'] = None
    except Exception as e:
        print(f"Warning: failed to process file {file_path}: {e}")

    for bucket_dt, b in buckets.items():
        flapping_set = set()
        for pfx, hist in prefix_history.items():
            if any(t == 'A' for t in hist) and any(t == 'W' for t in hist):
                flapping_set.add(pfx)
        b['flapping_prefixes'] |= flapping_set

    elapsed = time.time() - start_t
    logger.info(f"File processed: {os.path.basename(file_path)} lines={line_count} relevant={relevant_count} buckets={len(buckets)} elapsed={elapsed:.2f}s")
    return {bucket.isoformat(): finalize_bucket_feature(b) for bucket, b in buckets.items()}


def extract_timeseries_for_as(update_files, target_as_set):
    if not update_files:
        return {}
    results = {}
    files = [str(p) for p in update_files]
    target_as_list = list(target_as_set)

    if USE_PROCESSES:
        from concurrent.futures import ProcessPoolExecutor, as_completed
        total = len(files)
        completed = 0
        actual_workers = min(MAX_WORKERS, max(1, total // 2))
        logger.info(f"Starting ProcessPool: files={total} workers={actual_workers} (max={MAX_WORKERS}) bucket={BUCKET_MINUTES}min")
        with ProcessPoolExecutor(max_workers=actual_workers) as ex:
            futures = [ex.submit(process_single_file_timeseries, fp, target_as_list) for fp in files]
            for fut in as_completed(futures):
                part = fut.result()
                for ts, feat in part.items():
                    if ts not in results:
                        results[ts] = feat
                    else:
                        dst = results[ts]
                        dst['announcement_count'] += feat['announcement_count']
                        dst['withdrawal_count'] += feat['withdrawal_count']
                        dst['total_messages'] += feat['total_messages']
                        dst['announced_prefix_count'] += feat['announced_prefix_count']
                        dst['withdrawn_prefix_count'] += feat['withdrawn_prefix_count']
                        dst['unique_prefix_count'] += feat['unique_prefix_count']
                        dst['flapping_prefix_count'] += feat['flapping_prefix_count']
                        n1 = results[ts].get('_weight', results[ts]['total_messages']) if '_weight' in results[ts] else results[ts]['total_messages']
                        n2 = feat['total_messages']
                        if 'avg_path_length' in dst:
                            dst['avg_path_length'] = (
                                (dst['avg_path_length'] * n1 + feat['avg_path_length'] * n2) / (n1 + n2 if (n1 + n2) > 0 else 1)
                            )
                        else:
                            dst['avg_path_length'] = feat['avg_path_length']
                        dst['max_path_length'] = max(dst.get('max_path_length', 0), feat.get('max_path_length', 0))
                        min_existing = dst.get('min_path_length', 0)
                        dst['min_path_length'] = min(min_existing if min_existing > 0 else feat.get('min_path_length', 0), feat.get('min_path_length', 0))
                        dst['_weight'] = n1 + n2
                completed += 1
                if completed % max(1, total // 20) == 0 or completed == total:
                    logger.info(f"Processed files: {completed}/{total} ({completed*100//total}%)")
    else:
        logger.info(f"Starting sequential processing: files={len(files)} bucket={BUCKET_MINUTES}min")
        for fp in files:
            part = process_single_file_timeseries(fp, target_as_list)
            for ts, feat in part.items():
                if ts not in results:
                    results[ts] = feat
                else:
                    dst = results[ts]
                    dst['announcement_count'] += feat['announcement_count']
                    dst['withdrawal_count'] += feat['withdrawal_count']
                    dst['total_messages'] += feat['total_messages']
                    dst['announced_prefix_count'] += feat['announced_prefix_count']
                    dst['withdrawn_prefix_count'] += feat['withdrawn_prefix_count']
                    dst['unique_prefix_count'] += feat['unique_prefix_count']
                    dst['flapping_prefix_count'] += feat['flapping_prefix_count']
                    n1 = results[ts].get('_weight', results[ts]['total_messages']) if '_weight' in results[ts] else results[ts]['total_messages']
                    n2 = feat['total_messages']
                    if 'avg_path_length' in dst:
                        dst['avg_path_length'] = (
                            (dst['avg_path_length'] * n1 + feat['avg_path_length'] * n2) / (n1 + n2 if (n1 + n2) > 0 else 1)
                        )
                    else:
                        dst['avg_path_length'] = feat['avg_path_length']
                    dst['max_path_length'] = max(dst.get('max_path_length', 0), feat.get('max_path_length', 0))
                    min_existing = dst.get('min_path_length', 0)
                    dst['min_path_length'] = min(min_existing if min_existing > 0 else feat.get('min_path_length', 0), feat.get('min_path_length', 0))
                    dst['_weight'] = n1 + n2

    for v in results.values():
        if '_weight' in v:
            del v['_weight']
    return results


def calculate_baseline(features):
    if not features or features.get('total_messages', 0) == 0:
        return {}
    
    return {
        'avg_announcement_count': features.get('announcement_count', 0),
        'avg_withdrawal_count': features.get('withdrawal_count', 0),
        'avg_announced_prefix_count': features.get('announced_prefix_count', 0),
        'avg_withdrawn_prefix_count': features.get('withdrawn_prefix_count', 0),
        'avg_unique_prefix_count': features.get('unique_prefix_count', 0),
        'avg_flapping_prefix_count': features.get('flapping_prefix_count', 0),
        'avg_total_messages': features.get('total_messages', 0),
        'avg_path_length': features.get('avg_path_length', 0),
    }


def detect_anomalies(event_features, baseline_features):
    if not baseline_features:
        return []
    
    anomalies = []
    
    baseline_stats = {}
    for key in ['announcement_count', 'withdrawal_count', 'announced_prefix_count', 
                'withdrawn_prefix_count', 'unique_prefix_count', 'flapping_prefix_count',
                'total_messages', 'avg_path_length']:
        values = [b.get(key, 0) for b in baseline_features if key in b]
        if values:
            import numpy as np
            baseline_stats[key] = {
                'mean': np.mean(values),
                'std': np.std(values),
                'min': np.min(values),
                'max': np.max(values),
            }
    
    for key, stats in baseline_stats.items():
        event_value = event_features.get(key, 0)
        mean = stats['mean']
        std = stats['std']
        
        if mean == 0:
            if event_value > 0:
                anomalies.append({
                    'feature': key,
                    'event_value': event_value,
                    'baseline_mean': mean,
                    'anomaly_type': 'non_zero_when_baseline_zero',
                    'severity': 'high',
                })
        else:
            z_score = (event_value - mean) / std if std > 0 else 0
            
            if abs(z_score) >= Z_SCORE_THRESHOLD:
                anomaly_type = 'high_increase' if z_score > 0 else 'high_decrease'
                severity = 'high'
                
                anomalies.append({
                    'feature': key,
                    'event_value': event_value,
                    'baseline_mean': mean,
                    'baseline_std': std,
                    'z_score': z_score,
                    'anomaly_type': anomaly_type,
                    'severity': severity,
                })
    
    # Check specific anomaly patterns   
    # 1. Withdrawal count anomaly high
    if 'withdrawal_count' in event_features and 'withdrawal_count' in baseline_stats:
        withdraw_increase = event_features['withdrawal_count'] / baseline_stats['withdrawal_count']['mean'] if baseline_stats['withdrawal_count']['mean'] > 0 else 0
        if withdraw_increase > 5:
            anomalies.append({
                'feature': 'withdrawal_surge',
                'event_value': event_features['withdrawal_count'],
                'baseline_mean': baseline_stats['withdrawal_count']['mean'],
                'increase_ratio': withdraw_increase,
                'anomaly_type': 'withdrawal_surge',
                'severity': 'high',
            })
    
    # 2. Route flapping increase
    if 'flapping_prefix_count' in event_features and 'flapping_prefix_count' in baseline_stats:
        flapping_increase = event_features['flapping_prefix_count'] / baseline_stats['flapping_prefix_count']['mean'] if baseline_stats['flapping_prefix_count']['mean'] > 0 else 0
        if flapping_increase > 3 and event_features['flapping_prefix_count'] > 10:
            anomalies.append({
                'feature': 'route_flapping',
                'event_value': event_features['flapping_prefix_count'],
                'baseline_mean': baseline_stats['flapping_prefix_count']['mean'],
                'increase_ratio': flapping_increase,
                'anomaly_type': 'route_flapping',
                'severity': 'high',
            })
    
    # 3. Announcement count anomaly decrease
    if 'announcement_count' in event_features and 'announcement_count' in baseline_stats:
        announce_decrease = event_features['announcement_count'] / baseline_stats['announcement_count']['mean'] if baseline_stats['announcement_count']['mean'] > 0 else 0
        if announce_decrease < 0.5 and baseline_stats['announcement_count']['mean'] > 100:
            anomalies.append({
                'feature': 'announcement_drop',
                'event_value': event_features['announcement_count'],
                'baseline_mean': baseline_stats['announcement_count']['mean'],
                'decrease_ratio': announce_decrease,
                'anomaly_type': 'announcement_drop',
                'severity': 'high',
            })
    
    return anomalies


def detect_anomalies_timeseries(event_ts, baseline_ts):
    if not event_ts or not baseline_ts:
        return []
    import numpy as np
    features = [
        # Basic message stats
        'announcement_count',
        'withdrawal_count',
        'flapping_prefix_count',
        'unique_prefix_count',
        
        # Route change features
        'ori_change_rate',
        'num_ori_change',
        'origin_change_count',
        'path_change_rate',
        
        # Message behavior features
        'dup_A_rate',
        'avg_arrival_interval',
        
        # Path diversity features
        'editDis_entropy',
        'unique_as_count',
        
        # Peer AS and path length features
        'unique_peer_as_count',
        'avg_path_length',
        'max_path_length',
        'min_path_length',
    ]
    stats = {}
    for k in features:
        vals = [b.get(k, 0) for b in baseline_ts.values() if k in b]
        if not vals:
            continue
        stats[k] = {
            'mean': float(np.mean(vals)),
            'std': float(np.std(vals)),
        }
    anomalies = []
    for ts, feat in sorted(event_ts.items()):
        for k, st in stats.items():
            mean = st['mean']
            std = st['std']
            x = feat.get(k, 0)
            if std > 0:
                z = (x - mean) / std
            else:
                z = 0.0
            if (std == 0 and x != mean) or abs(z) >= Z_SCORE_THRESHOLD:
                anomalies.append({
                    'timestamp': ts,
                    'feature': k,
                    'value': x,
                    'baseline_mean': mean,
                    'baseline_std': std,
                    'z_score': z,
                    'anomaly_type': 'high_increase' if (std == 0 and x > mean) or z > 0 else 'high_decrease',
                    'severity': 'high'
                })
    return anomalies


def detect_anomalies_timeseries_periodic(event_ts, baseline_ts_dict):
    """
    Detect anomalies using multiple baseline periods.
    Uses mean and std computed across all baseline periods for each time slot.

    Args:
        event_ts: dict of timestamp -> features for event window
        baseline_ts_dict: dict of period_index -> (timestamp -> features)

    Returns:
        list of anomaly dicts with timestamp, feature, z_score, etc.
    """
    if not event_ts or not baseline_ts_dict:
        return []

    import numpy as np

    features = [
        'announcement_count',
        'withdrawal_count',
        'flapping_prefix_count',
        'unique_prefix_count',
        'ori_change_rate',
        'num_ori_change',
        'origin_change_count',
        'path_change_rate',
        'dup_A_rate',
        'avg_arrival_interval',
        'editDis_entropy',
        'unique_as_count',
        'unique_peer_as_count',
        'avg_path_length',
        'max_path_length',
        'min_path_length',
    ]

    # Align baseline periods by relative time offset within the period
    # Group by relative time (e.g., "15:30", "15:35" from period start)
    aligned_baseline = {}  # relative_time -> {feature: [values from each period]}

    for period_idx, period_ts in baseline_ts_dict.items():
        # Get sorted timestamps to establish relative position
        sorted_times = sorted(period_ts.keys())
        if not sorted_times:
            continue

        period_start_time = sorted_times[0]
        for ts_str, features_dict in period_ts.items():
            # Calculate relative time from period start
            ts_dt = datetime.fromisoformat(ts_str)
            if period_start_time:
                start_dt = datetime.fromisoformat(period_start_time)
                relative_minutes = int((ts_dt - start_dt).total_seconds() / 60)
                relative_key = f"offset_{relative_minutes // 5}"  # 5-min buckets

                if relative_key not in aligned_baseline:
                    aligned_baseline[relative_key] = {f: [] for f in features}

                for f in features:
                    if f in features_dict:
                        aligned_baseline[relative_key][f].append(features_dict[f])

    # Compute stats for each relative time slot
    stats_by_relative_time = {}
    for relative_key, feature_vals in aligned_baseline.items():
        stats_by_relative_time[relative_key] = {}
        for f, vals in feature_vals.items():
            if vals:
                stats_by_relative_time[relative_key][f] = {
                    'mean': float(np.mean(vals)),
                    'std': float(np.std(vals)),
                }

    # Detect anomalies by comparing each event bucket to aligned baseline
    anomalies = []
    for ts_str, event_feat in event_ts.items():
        # Find relative time for this bucket
        # For simplicity, use the first baseline period to get relative position
        if not baseline_ts_dict:
            continue

        first_period_ts = baseline_ts_dict.get(0, {})
        if not first_period_ts:
            continue

        sorted_baseline_times = sorted(first_period_ts.keys())
        if not sorted_baseline_times:
            continue

        period_start_time = sorted_baseline_times[0]
        ts_dt = datetime.fromisoformat(ts_str)
        start_dt = datetime.fromisoformat(period_start_time)
        relative_minutes = int((ts_dt - start_dt).total_seconds() / 60)
        relative_key = f"offset_{relative_minutes // 5}"

        if relative_key not in stats_by_relative_time:
            continue

        stats = stats_by_relative_time[relative_key]
        for f, st in stats.items():
            mean = st['mean']
            std = st['std']
            x = event_feat.get(f, 0)

            if std > 0:
                z = (x - mean) / std
            else:
                z = 0.0

            if abs(z) >= 3.0:
                anomalies.append({
                    'timestamp': ts_str,
                    'relative_time': relative_key,
                    'feature': f,
                    'value': x,
                    'baseline_mean': mean,
                    'baseline_std': std,
                    'z_score': z,
                    'anomaly_type': 'high_increase' if z > 0 else 'high_decrease',
                    'severity': 'high' if abs(z) >= 3.0 else 'medium',
                })

    return anomalies


def process_event(row):
    event_name = row.get('event_name', 'unknown')
    print(f"\nProcessing event: {event_name}")
    
    try:
        start_time = parse_datetime(row['start_time'])
        end_time = parse_datetime(row['end_time'])
        
        outage_as = parse_as_list(row.get('outage_as', ''))
        if not outage_as:
            print(f"  Warning: event {event_name} has no outage_as, skip")
            return None
        
        print(f"  Time window: {start_time} to {end_time}")
        print(f"  Related AS set: {outage_as}")
        
        plot_window_start = start_time - timedelta(days=1)
        plot_window_end = end_time + timedelta(days=1)
        
        event_window_start = start_time
        event_window_end = end_time
        
        baseline_window_start = plot_window_start
        baseline_window_end = start_time
        
        print(f"  Finding plot-window files (start_time-1day ~ end_time+1day)...")
        step_t = time.time()
        plot_files = find_update_files(plot_window_start, plot_window_end)
        print(f"    Found {len(plot_files)} files")
        logger.info(f"Plot window files found: {len(plot_files)} elapsed={time.time()-step_t:.2f}s")
        
        def parse_file_time(filepath):
            try:
                parts = filepath.stem.split('.')
                if len(parts) >= 2:
                    time_str = parts[1]  # YYYYMMDD.HHMM
                    return datetime.strptime(time_str, '%Y%m%d.%H%M')
            except:
                pass
            return datetime.min
        
        event_files = [f for f in plot_files if event_window_start <= parse_file_time(f) <= event_window_end]
        baseline_files = [f for f in plot_files if baseline_window_start <= parse_file_time(f) < baseline_window_end]
        post_event_files = [f for f in plot_files if end_time < parse_file_time(f) <= plot_window_end]
        
        print(f"  Event window files: {len(event_files)}")
        print(f"  Baseline window files: {len(baseline_files)}")
        print(f"  Post-event window files: {len(post_event_files)}")
        
        if not plot_files:
            print(f"  Warning: no data files found for plot window")
        
        print(f"  Extracting full plot-window features...")
        step_t = time.time()
        plot_ts = extract_timeseries_for_as(plot_files, outage_as) if plot_files else {}
        logger.info(f"Plot timeseries buckets: {len(plot_ts)}; elapsed={time.time()-step_t:.2f}s")
        
        event_ts = {}
        baseline_ts = {}
        for ts_str, features in plot_ts.items():
            ts = datetime.fromisoformat(ts_str)
            if event_window_start <= ts <= event_window_end:
                event_ts[ts_str] = features
            elif baseline_window_start <= ts < baseline_window_end:
                baseline_ts[ts_str] = features
        
        event_features = _aggregate_timeseries_to_totals(event_ts) if event_ts else {}
        
        baseline_samples = []
        if baseline_ts:
            baseline_features_full = _aggregate_timeseries_to_totals(baseline_ts)
            baseline_samples.append(baseline_features_full)
        
        print(f"  Detecting anomalies...")
        step_t = time.time()
        anomalies = []
        if baseline_samples:
            # per-5min anomalies
            anomalies = detect_anomalies_timeseries(event_ts, baseline_ts)
        logger.info(f"Anomalies computed: {len(anomalies)} elapsed={time.time()-step_t:.2f}s")
        
        csv_output_dir = OUTPUT_DIR / "timeseries_csv"
        csv_output_dir.mkdir(parents=True, exist_ok=True)
        
        if plot_ts:
            csv_data = []
            for ts_str, features in plot_ts.items():
                try:
                    ts_dt = datetime.fromisoformat(ts_str)
                    row = {'timestamp': ts_dt.strftime('%Y-%m-%d %H:%M:%S')}
                except:
                    row = {'timestamp': ts_str}
                row.update(features)
                csv_data.append(row)
            
            if csv_data:
                df_csv = pd.DataFrame(csv_data)
                df_csv['timestamp'] = pd.to_datetime(df_csv['timestamp'])
                df_csv = df_csv.sort_values('timestamp')
                df_csv['timestamp'] = df_csv['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
                
                feature_columns = [
                    'announcement_count',
                    'withdrawal_count',
                    'flapping_prefix_count',
                    'ori_change_rate',
                    'num_ori_change',
                    'path_change_rate',
                    'dup_A_rate',
                    'avg_arrival_interval',
                    'editDis_entropy',
                    'unique_as_count'
                ]
                available_columns = ['timestamp'] + [col for col in feature_columns if col in df_csv.columns]
                df_csv = df_csv[available_columns]
                
                csv_file = csv_output_dir / f"{event_name}_timeseries.csv"
                df_csv.to_csv(csv_file, index=False, encoding='utf-8')
                print(f"  Saved timeseries CSV: {csv_file} ({len(df_csv)} rows, {len(available_columns)-1} features)")
        
        result = {
            'event_name': event_name,
            'event_type': row.get('event_type', ''),
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'outage_as': sorted(list(outage_as)),
            'event_features': event_features,
            'baseline_features': baseline_samples[0] if baseline_samples else {},
            'anomalies': anomalies,
            'timeseries_event': event_ts,
            'timeseries_baseline': baseline_ts,
            'timeseries_plot': plot_ts,
            'timeseries_baseline_size': len(baseline_ts),
            'csv_file': str(csv_output_dir / f"{event_name}_timeseries.csv") if plot_ts else None,
        }
        
        print(f"  Done: detected {len(anomalies)} anomalous features")
        
        return result
        
    except Exception as e:
        print(f"  Error: failed to process event {event_name}: {e}")
        import traceback
        traceback.print_exc()
        return None


def main():
    print("=" * 80)
    print("BGP Event Feature Extraction")
    print("=" * 80)
    
    if not CSV_FILE.exists():
        print(f"Error: CSV file not found: {CSV_FILE}")
        return
    
    print(f"Reading events table: {CSV_FILE}")
    df = pd.read_csv(CSV_FILE)
    print(f"Found {len(df)} events")
    
    results = []
    for idx, row in df.iterrows():
        result = process_event(row)
        if result:
            results.append(result)
    
    output_file = OUTPUT_DIR / "event_features_analysis.json"
    print(f"\nSaving results to: {output_file}")
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False, default=str)
    
    print("\nGenerating summary report...")
    summary_file = OUTPUT_DIR / "event_features_summary.txt"
    with open(summary_file, 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("BGP Event Anomaly Feature Summary\n")
        f.write("=" * 80 + "\n\n")
        
        for result in results:
            f.write(f"Event: {result['event_name']}\n")
            f.write(f"Type: {result['event_type']}\n")
            f.write(f"Time: {result['start_time']} to {result['end_time']}\n")
            f.write(f"Related AS: {', '.join(map(str, result['outage_as']))}\n")
            f.write(f"\nAnomaly count: {len(result['anomalies'])}\n")
            
            if result['anomalies']:
                f.write("\nAnomaly details:\n")
                for anomaly in result['anomalies']:
                    f.write(f"  - {anomaly['feature']}: {anomaly.get('anomaly_type', 'unknown')} ")
                    f.write(f"(severity: {anomaly.get('severity', 'unknown')})\n")
                    if 'event_value' in anomaly:
                        f.write(f"    event_value: {anomaly['event_value']}\n")
                    if 'baseline_mean' in anomaly:
                        f.write(f"    baseline_mean: {anomaly['baseline_mean']:.2f}\n")
                    if 'increase_ratio' in anomaly:
                        f.write(f"    increase_ratio: {anomaly['increase_ratio']:.2f}x\n")
                    if 'decrease_ratio' in anomaly:
                        f.write(f"    decrease_ratio: {anomaly['decrease_ratio']:.2f}x\n")
            else:
                f.write("  No significant anomalies detected\n")
            
            f.write("\n" + "-" * 80 + "\n\n")
    
    print(f"Summary saved to: {summary_file}")
    print(f"\nDone. Processed {len(results)} events")


if __name__ == "__main__":
    main()

