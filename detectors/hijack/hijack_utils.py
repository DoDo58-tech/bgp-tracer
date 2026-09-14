import os
import sys
import json
import polars as pl
from typing import Any, Dict, List, Optional, Set, Tuple
from datetime import datetime
from pathlib import Path

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from config import DEFAULT_ANOMALY_THRESHOLD

class SimpleLogger:
    def info(self, msg):
        print(f"[HIJACK INFO] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {msg}")

    def warning(self, msg):
        print(f"[HIJACK WARN] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {msg}")

    def error(self, msg):
        print(f"[HIJACK ERROR] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {msg}")

logger = SimpleLogger()

def remove_consecutive_duplicates(as_path):
    if not as_path:
        return ''
    as_list = as_path.split()
    seen = []
    for a in as_list:
        if not seen or seen[-1] != a:
            seen.append(a)
    return ' '.join(seen)


def remove_consecutive_duplicates_fast(as_path_str):
    if not as_path_str:
        return ''
    parts = as_path_str.split()
    if len(parts) <= 1:
        return as_path_str
    result = [parts[0]]
    for p in parts[1:]:
        if p != result[-1]:
            result.append(p)
    return ' '.join(result)


def find_common_path_endings(as_paths, threshold=DEFAULT_ANOMALY_THRESHOLD):
    if not as_paths or len(as_paths) < 2:
        return []

    total_paths = len(as_paths)
    min_count = max(2, int(total_paths * threshold))

    ending_counts = {}
    for path in as_paths:
        if not path:
            continue
        parts = path.split()
        for i in range(len(parts)):
            ending = tuple(parts[i:])
            ending_counts[ending] = ending_counts.get(ending, 0) + 1

    common_endings = []
    for ending, count in ending_counts.items():
        if count >= min_count:
            common_endings.append({
                'ending': list(ending),
                'count': count,
                'fraction': count / total_paths
            })

    common_endings.sort(key=lambda x: x['count'], reverse=True)
    return common_endings


def check_fake_connections_in_df(df, as_relationships, use_disk_cache = False,
                               asrel_file_paths = None,
                               early_exit = False, use_ultra_fast = False):
    if not isinstance(df, pl.DataFrame):
        df = pl.DataFrame(df)
    
    logger.info(f"Checking fake connections in {len(df)} announcements")

    if df.is_empty():
        return df

    as_pairs = build_as_pair_set(as_relationships)

    fake_connections_found = 0
    updated_rows = []

    for row in df.iter_rows(named=True):
        as_path_str = str(row.get('as-path', ''))

        if not as_path_str:
            row_dict = dict(row)
            row_dict['has_fake_connect'] = False
            row_dict['fake_connections'] = []
            row_dict['exact_fake_connect'] = ''
            updated_rows.append(row_dict)
            continue

        as_path = as_path_str.split()
        fake_connections = []

        for i in range(len(as_path) - 1):
            as1, as2 = as_path[i], as_path[i + 1]
            pair = (as1, as2)

            if pair not in as_pairs:
                fake_connections.append({
                    'as1': as1,
                    'as2': as2,
                    'position': i,
                    'path': as_path_str
                })

        row_dict = dict(row)
        row_dict['has_fake_connect'] = len(fake_connections) > 0
        if fake_connections:
            row_dict['fake_connections'] = fake_connections
            row_dict['exact_fake_connect'] = f"{fake_connections[0]['as1']}|{fake_connections[0]['as2']}"
            fake_connections_found += 1
        else:
            row_dict['fake_connections'] = []
            row_dict['exact_fake_connect'] = ''

        updated_rows.append(row_dict)

    logger.info(f"Found {fake_connections_found} announcements with fake connections")

    return pl.DataFrame(updated_rows)


def build_as_pair_set(as_relationships):
    as_pairs = set()

    providers_map = as_relationships.get('providers', {})
    peers_map = as_relationships.get('peers', {})

    for customer, providers in providers_map.items():
        for provider in providers:
            as_pairs.add((provider, customer))  # provider -> customer
            as_pairs.add((customer, provider))  # customer -> provider (for path traversal)

    # Add peer relationships (bidirectional)
    for as1, peers in peers_map.items():
        for as2 in peers:
            as_pairs.add((as1, as2))
            as_pairs.add((as2, as1))

    return as_pairs


def check_fake_connections_single_row(row_dict, as_pairs):
    as_path_str = str(row_dict.get('as-path', ''))
    timestamp = row_dict.get('timestamp', '')

    if not as_path_str:
        return []

    as_path = as_path_str.split()
    fake_connections = []

    for i in range(len(as_path) - 1):
        as1, as2 = as_path[i], as_path[i + 1]
        pair = (as1, as2)

        if pair not in as_pairs:
            fake_connections.append({
                'as1': as1,
                'as2': as2,
                'position': i,
                'path': as_path_str,
                'timestamp': timestamp
            })

    return fake_connections
