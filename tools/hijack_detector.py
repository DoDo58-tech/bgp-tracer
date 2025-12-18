import os
import sys
import json
import gc
import re
import pandas as pd
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Set, Tuple, Any, Optional
import psutil
from dateutil.relativedelta import relativedelta

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from data.updates_loader import get_updates_streaming
from data.prefix2as_loader import process_prefix2as
from data.asorg_loader import process_asorg
from data.asrel_loader import process_asrel, load_asrel
from utils.logger import logger
from utils.bgp_utils import (
    find_common_path_endings,
    PrefixTrie,
    check_fake_connections_in_df,
    remove_consecutive_duplicates
)
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Cache persisted to disk: fake-connection frequency keyed by
# (fake_connection, YYYY-MM-DD) to avoid re-validating the same pair within the
# same day across multiple AS runs/processes.
_FAKE_CONN_CACHE_DIR = PROJECT_ROOT / "cache"
_FAKE_CONN_CACHE_FILE = _FAKE_CONN_CACHE_DIR / "fake_conn_freq_cache.json"
_FAKE_CONN_FREQ_CACHE: Dict[Tuple[str, str], Dict[str, Any]] = {}
_FAKE_CONN_CACHE_LOADED = False


def _load_fake_conn_cache():
    """Load fake connection cache from disk once per process."""
    global _FAKE_CONN_FREQ_CACHE, _FAKE_CONN_CACHE_LOADED
    if _FAKE_CONN_CACHE_LOADED:
        return
    try:
        if _FAKE_CONN_CACHE_FILE.exists():
            with open(_FAKE_CONN_CACHE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            # Stored as {"fake|date": {...}}
            cache = {}
            for k, v in data.items():
                if "|" in k:
                    fake_conn, day_str = k.split("|", 1)
                    cache[(fake_conn, day_str)] = v
            _FAKE_CONN_FREQ_CACHE = cache
    except Exception as e:
        logger.warning(f"Failed to load fake connection cache: {e}")
    finally:
        _FAKE_CONN_CACHE_LOADED = True


def _save_fake_conn_cache():
    """Persist fake connection cache to disk."""
    try:
        _FAKE_CONN_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        to_dump = {f"{k[0]}|{k[1]}": v for k, v in _FAKE_CONN_FREQ_CACHE.items()}
        with open(_FAKE_CONN_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(to_dump, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.warning(f"Failed to save fake connection cache: {e}")


def get_target_prefixes(target_as, prefix_to_as):
    return {prefix for prefix, asn in prefix_to_as.items() if asn == target_as}


def get_target_prefixes_batch(target_as_list, prefix_to_as):
    """Get target prefixes for multiple AS numbers
    
    Args:
        target_as_list: List of AS numbers to get prefixes for
        prefix_to_as: Mapping of prefix to AS number
    
    Returns:
        Dict mapping AS number to set of prefixes
    """
    prefixes_by_as = {}
    for asn in target_as_list:
        asn_clean = str(asn).replace('AS', '').replace('as', '')
        prefixes_by_as[asn_clean] = {
            prefix for prefix, mapped_asn in prefix_to_as.items() 
            if mapped_asn == asn_clean
        }
    return prefixes_by_as


def load_historical_as_relationships(start_time, months_back=0):
    months_back = max(0, int(months_back or 0))
    current_time = start_time.replace(day=1)
    
    asrel_files = []
    seen_files = set()

    for _ in range(months_back+1):
        asrel_path = process_asrel(current_time)
 
        if asrel_path and Path(asrel_path).exists():
            if asrel_path not in seen_files:
                asrel_files.append(asrel_path)
                seen_files.add(asrel_path)
            else:
                logger.warning("Skipping duplicate AS-rel file: %s", asrel_path)
        else:
            logger.warning("No AS-rel file for %s", current_time.strftime("%Y-%m"))

        current_time -= relativedelta(months=1)

    if not asrel_files:
        logger.error("No AS relationship files found for the historical period")
        return {'providers': {}, 'peers': {}}
    
    merged_providers = {}
    merged_peers = {}
    
    for file_path in asrel_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Merge providers - combine all providers from all months
            for asn, providers in data.get('providers', {}).items():
                if asn not in merged_providers:
                    merged_providers[asn] = set()
                if isinstance(providers, (list, tuple)):
                    merged_providers[asn].update(providers)
            
            # Merge peers - combine all peers from all months
            for asn, peers in data.get('peers', {}).items():
                if asn not in merged_peers:
                    merged_peers[asn] = set()
                if isinstance(peers, (list, tuple)):
                    merged_peers[asn].update(peers)
                
        except Exception as e:
            logger.error(f"Error loading AS-rel file {file_path}: {e}")
            continue
    
    result = {
        'providers': {asn: list(providers) for asn, providers in merged_providers.items()},
        'peers': {asn: list(peers) for asn, peers in merged_peers.items()},
        '_file_paths': asrel_files  # Store file paths for cache key generation
    }
    
    return result


def _pick_timestamp(current, candidate, prefer_min=True):
    if candidate in (None, '', []):
        return current
    if current in (None, '', []):
        return candidate
    try:
        cand_dt = pd.to_datetime(candidate)
        curr_dt = pd.to_datetime(current)
        if pd.isna(cand_dt):
            return current
        if pd.isna(curr_dt):
            return candidate
        if prefer_min:
            return candidate if cand_dt < curr_dt else current
        return candidate if cand_dt > curr_dt else current
    except Exception:
        return current


def aggregate_anomalies(anomalies):
    summary = {}
    for anomaly in anomalies:
        if not isinstance(anomaly, dict):
            continue
        victim = anomaly.get('victim_as') or anomaly.get('expected_origin') or "unknown"
        a_type = anomaly.get('type') or anomaly.get('detection_status') or "unknown"
        key = (victim, a_type)
        entry = summary.setdefault(
            key,
            {
                'victim_as': victim,
                'type': a_type,
                'count': 0,
                'prefixes': set(),
                'hijackers': set(),
                'first_seen': None,
                'last_seen': None,
            },
        )
        entry['count'] += 1
        prefix = anomaly.get('prefix')
        if prefix:
            entry['prefixes'].add(prefix)
        hijacker = anomaly.get('hijacker_as') or anomaly.get('most_suspicious_hijacker') or anomaly.get('suspicious_hijacker')
        if isinstance(hijacker, (list, set, tuple)):
            entry['hijackers'].update(str(h) for h in hijacker if h)
        elif hijacker:
            entry['hijackers'].add(str(hijacker))
        entry['first_seen'] = _pick_timestamp(entry['first_seen'], anomaly.get('first_seen') or anomaly.get('timestamp'), prefer_min=True)
        entry['last_seen'] = _pick_timestamp(entry['last_seen'], anomaly.get('last_seen') or anomaly.get('timestamp'), prefer_min=False)
    aggregated = []
    for entry in summary.values():
        entry['prefixes'] = sorted(entry['prefixes'])
        entry['hijackers'] = sorted(entry['hijackers'])
        aggregated.append(entry)
    return aggregated


def filter_related_updates(updates_df, target_prefixes):
    trie = PrefixTrie()
    for tp in target_prefixes:
        trie.insert(tp)
    
    updates_df = updates_df.copy()
    updates_df['ip_related'] = updates_df['prefix'].apply(lambda p: trie.has_ancestor(p))
    
    return updates_df

def check_origin_hijack_vectorized(row, prefix_to_as, prefix_trie, sorted_prefixes=None):
    prefix = row['prefix']
    origin_as = row['origin-as']
    timestamp = row['timestamp']
    row_dict = row.to_dict()
    
    if prefix in prefix_to_as:
        expected_origin = prefix_to_as[prefix]
        if origin_as != expected_origin:
            row_dict.update({
                'type': 'origin_hijack',
                'attack_type': 'origin_hijack',
                'prefix': prefix,
                'hijacker_as': origin_as,
                'expected_origin': expected_origin,
                'victim_as': expected_origin,
                'timestamp': timestamp,
                'parent_prefix': prefix,
            })
            return row_dict
    else:
        parent_prefix, expected_origin = prefix_trie.find_most_specific_ancestor(prefix, prefix_to_as)
        
        if parent_prefix:
            # Only report as hijack if the origin AS is different from expected
            if origin_as != expected_origin:
                row_dict.update({
                    'type': 'subprefix_hijack',
                    'attack_type': 'subprefix_hijack',
                    'prefix': prefix,
                    'hijacker_as': origin_as,
                    'expected_origin': expected_origin,
                    'victim_as': expected_origin,
                    'timestamp': timestamp,
                    'parent_prefix': parent_prefix,
                })
                return row_dict
            # If origin_as == expected_origin, this is a legitimate more specific announcement
            # No hijack detected
            return None
    return None


def detect_origin_hijacks(announcements, prefix_to_as):
    # Only process announcements without fake connections (if the column exists)
    if 'has_fake_connect' in announcements.columns:
        announcements = announcements[announcements['has_fake_connect'] == False]
    
    prefix_trie = PrefixTrie()
    for prefix in prefix_to_as.keys():
        prefix_trie.insert(prefix)
    
    # Create sorted list of prefixes for efficient matching (most specific first)
    sorted_prefixes = sorted(prefix_to_as.items(), key=lambda x: int(x[0].split('/')[1]), reverse=True)
    
    potential_hijacks = announcements.apply(
        check_origin_hijack_vectorized, 
        axis=1, 
        prefix_to_as=prefix_to_as,
        prefix_trie=prefix_trie,
        sorted_prefixes=sorted_prefixes
    ).dropna()
    
    return list(potential_hijacks)


def batch_check_connection_frequency(
    anomaly_groups,
    validate_with_updates=True,
    update_workers: int = 1,
    io_busy_threshold: int = 85,
):
    if not validate_with_updates or not anomaly_groups:
        return {}
    
    from datetime import timedelta
    from data.updates_loader import get_updates_streaming
    
    _load_fake_conn_cache()
    
    # Collect all fake connections and their check times
    fake_connections_to_check = {}
    cache_hits: Dict[str, int] = {}
    for key, group in anomaly_groups.items():
        fake_connection = group.get('fake_connection', '')
        if not fake_connection or pd.isna(fake_connection):
            continue
        
        # Parse first_seen to get check time
        first_seen_raw = group.get('first_seen')
        if isinstance(first_seen_raw, datetime):
            check_time = first_seen_raw
        elif isinstance(first_seen_raw, str):
            try:
                check_time = datetime.strptime(first_seen_raw, "%Y-%m-%d %H:%M:%S")
            except Exception:
                # If we cannot parse the timestamp string, skip this group
                continue
        else:
            # Unsupported type for first_seen, skip
            continue
        
        cache_key = (fake_connection, check_time.strftime("%Y-%m-%d"))
        cache_entry = _FAKE_CONN_FREQ_CACHE.get(cache_key)
        if cache_entry is not None:
            cache_hits[fake_connection] = cache_entry.get("frequency", 0)
            continue
        
        # Use the earliest check_time as the reference for time window
        if fake_connection not in fake_connections_to_check:
            fake_connections_to_check[fake_connection] = check_time
        else:
            fake_connections_to_check[fake_connection] = min(
                fake_connections_to_check[fake_connection], 
                check_time,
            )
    
    if not fake_connections_to_check and cache_hits:
        return cache_hits
    if not fake_connections_to_check:
        return {}
    
    # Parse all fake connection pairs
    fake_connection_pairs = {}
    for fake_connection in fake_connections_to_check.keys():
        fake_pairs = fake_connection.split(';')
        as_pairs = []
        for pair in fake_pairs:
            if '-' in pair:
                as_pairs.append(pair.strip())
        if as_pairs:
            fake_connection_pairs[fake_connection] = set(as_pairs)
    
    if not fake_connection_pairs:
        return {}
    
    # OPTIMIZATION 1: Build reverse index (AS pair -> list of fake connections)
    # This allows O(1) lookup instead of O(n) iteration
    as_pair_to_fake_connections = {}
    for fake_connection, as_pairs_set in fake_connection_pairs.items():
        for as_pair in as_pairs_set:
            if as_pair not in as_pair_to_fake_connections:
                as_pair_to_fake_connections[as_pair] = []
            as_pair_to_fake_connections[as_pair].append(fake_connection)
    
    # OPTIMIZATION 2: Extract all AS numbers involved in fake connections
    # This allows early filtering of paths that don't contain any relevant AS
    all_fake_connection_ases = set()
    for as_pair in as_pair_to_fake_connections.keys():
        try:
            as1, as2 = as_pair.split('-', 1)
            all_fake_connection_ases.add(as1.strip())
            all_fake_connection_ases.add(as2.strip())
        except ValueError:
            # Skip invalid AS pairs
            continue
    
    if not all_fake_connection_ases:
        logger.warning("No valid AS numbers found in fake connections")
        return {}
    
    # Use the earliest check_time to determine time window
    earliest_check_time = min(fake_connections_to_check.values())
    week_start = earliest_check_time - timedelta(days=7)
    week_end = earliest_check_time
    
    logger.info(
        f"Batch checking {len(fake_connection_pairs)} fake connections in past week "
        f"({week_start} to {week_end})"
    )
    logger.info(
        f"Optimization: Using reverse index with {len(as_pair_to_fake_connections)} AS pairs, "
        f"filtering for {len(all_fake_connection_ases)} unique AS numbers"
    )
    
    # Initialize frequency counters
    connection_frequencies = {fc: 0 for fc in fake_connection_pairs.keys()}
    
    try:
        # Single pass through all updates data
        total_paths_processed = 0
        total_paths_filtered = 0
        
        for df_chunk in get_updates_streaming(
            week_start,
            week_end,
            workers=update_workers,
            io_busy_threshold=io_busy_threshold,
        ):
            if df_chunk is None or df_chunk.empty:
                continue
            
            announcements_chunk = df_chunk[df_chunk['A/W'] == 'A']
            if announcements_chunk.empty:
                continue
            
            total_paths_processed += len(announcements_chunk)
            
            # OPTIMIZATION 2: Early filtering - only process paths containing fake connection ASes
            # This dramatically reduces the number of paths to check
            as_path_str = announcements_chunk['as-path'].astype(str)
            
            # Build regex pattern for fast filtering
            # Escape special regex characters in AS numbers
            escaped_ases = [re.escape(asn) for asn in all_fake_connection_ases]
            as_pattern = '|'.join(escaped_ases)
            
            # Filter: keep only paths that contain at least one fake connection AS
            relevant_mask = as_path_str.str.contains(
                as_pattern,
                na=False,
                regex=True
            )
            filtered_announcements = announcements_chunk[relevant_mask]
            total_paths_filtered += len(filtered_announcements)
            
            if filtered_announcements.empty:
                continue
            
            # OPTIMIZATION 1: Use reverse index for O(1) lookup
            # Check each filtered as-path against fake connections
            for as_path in filtered_announcements['as-path']:
                if pd.isna(as_path) or as_path == '':
                    continue
                
                path_segments = str(as_path).strip().split()
                if len(path_segments) < 2:
                    continue
                
                # Extract AS pairs from path
                for i in range(len(path_segments) - 1):
                    as_pair = f"{path_segments[i]}-{path_segments[i+1]}"
                    
                    # O(1) lookup using reverse index
                if as_pair in as_pair_to_fake_connections:
                        # This AS pair matches one or more fake connections
                    for fake_connection in as_pair_to_fake_connections[as_pair]:
                        connection_frequencies[fake_connection] += 1
        
        filter_ratio = (total_paths_processed - total_paths_filtered) / total_paths_processed if total_paths_processed > 0 else 0
        logger.info(
            f"Batch check completed. Processed {total_paths_processed:,} paths, "
            f"filtered to {total_paths_filtered:,} relevant paths "
            f"({filter_ratio*100:.1f}% reduction). Frequencies: {connection_frequencies}"
        )
        
    except Exception as e:
        logger.error(f"Error in batch checking connection frequency: {e}")
        return cache_hits
    
    # Merge cache hits and update cache for newly computed items
    for fc, freq in connection_frequencies.items():
        check_time = fake_connections_to_check.get(fc)
        if check_time:
            cache_key = (fc, check_time.strftime("%Y-%m-%d"))
            _FAKE_CONN_FREQ_CACHE[cache_key] = {
                "frequency": freq,
                "week_start": week_start.isoformat(),
                "week_end": week_end.isoformat(),
            }
    if cache_hits:
        connection_frequencies.update(cache_hits)
    
    # Persist updated cache
    _save_fake_conn_cache()
    
    return connection_frequencies


def detect_forge_hijacks(
    announcements,
    as_relationships_data,
    target_as,
    prefix_to_as,
    validate_with_updates=True,
    victim_default=None,
    update_workers: int = 1,
    io_busy_threshold: int = 85,
):
    logger.info(f"Starting MITM detection for AS{target_as} using current month AS relationships (months_back=0)")
    
    forge_df = announcements[announcements['has_fake_connect'] == True]
    
    if forge_df.empty:
        logger.info("No fake connections found in announcements")
        return []
    
    logger.info(f"Found {len(forge_df)} announcements with fake connections")
    
    anomaly_groups = {}
    
    processed_count = 0
    for idx, row in forge_df.iterrows():
        processed_count += 1
        if processed_count % 1000 == 0:
            logger.info(f"Processed {processed_count}/{len(forge_df)} fake connection announcements...")
        fake_connect = row.get('exact_fake_connect', '')
        if not fake_connect or pd.isna(fake_connect):
            continue
        
        key = (row['prefix'], fake_connect)
        
        timestamp_str = str(row['timestamp'])
        
        if key not in anomaly_groups:
            anomaly_groups[key] = {
                'prefix': row['prefix'],
                'fake_connection': fake_connect,
                'first_seen': timestamp_str,
                'last_seen': timestamp_str,
                'as_path': row['as-path'],
                'paths': [row['as-path']],
                'announcement_count': 1,
                'ip_related': bool(row.get('ip_related', True)),
            }
        else:
            anomaly_groups[key]['last_seen'] = max(
                anomaly_groups[key]['last_seen'], 
                timestamp_str
            )
            anomaly_groups[key]['announcement_count'] += 1
            if row['as-path'] not in anomaly_groups[key]['paths']:
                anomaly_groups[key]['paths'].append(row['as-path'])
            anomaly_groups[key]['ip_related'] = anomaly_groups[key]['ip_related'] or bool(row.get('ip_related', True))
    
    connection_frequencies = {}
    if validate_with_updates:
        logger.info(
            f"Validating {len(anomaly_groups)} fake connections against past week's updates..."
        )
        # Use batch validation for efficiency - all fake connections validated in one pass
        connection_frequencies = batch_check_connection_frequency(
            anomaly_groups,
            validate_with_updates=True,
            update_workers=update_workers,
            io_busy_threshold=io_busy_threshold,
        )
        logger.info(f"Validation completed: {len(connection_frequencies)} connections checked")
    else:
        logger.info(f"Skipping validation for {len(anomaly_groups)} fake connections (validate_with_updates=False)")
    
    group_results = {}
    for key, group in anomaly_groups.items():
        fake_pairs = group['fake_connection'].split(';')
        suspicious_ases = set()
        
        for pair in fake_pairs:
            if '-' in pair:
                ases = pair.split('-')
                suspicious_ases.update(ases)
        
        most_suspicious = "Unknown"
        if suspicious_ases:
            most_suspicious = list(suspicious_ases)[0]
        
        is_legitimate = False
        connection_frequency = connection_frequencies.get(group['fake_connection'], 0)
        
        if validate_with_updates:
            if connection_frequency >= 10:
                is_legitimate = True
                logger.info(
                    f"Fake connection {group['fake_connection']} appears "
                    f"{connection_frequency} times in past week - considered LEGITIMATE"
                )
            else:
                logger.info(
                    f"Fake connection {group['fake_connection']} appears "
                    f"{connection_frequency} times in past week - considered ILLEGAL"
                )
        if is_legitimate:
            risk_score = 0.2
            confidence = 'low'
            detection_status = 'legitimate_connection'
        else:
            risk_score = 0.9
            confidence = 'high'
            detection_status = 'illegal_connection'
        
        group_results[key] = {
            'type': 'mitm_hijack',
            'prefix': group['prefix'],
            'fake_connection': group['fake_connection'],
            'suspicious_hijacker': list(suspicious_ases),
            'most_suspicious_hijacker': most_suspicious,
            'suspicious_path': group['as_path'],
            'suspicious_paths': group['paths'],
            'first_seen': group['first_seen'],
            'last_seen': group['last_seen'],
            'announcement_count': group['announcement_count'],
            'risk_score': risk_score,
            'confidence': confidence,
            'is_legitimate': is_legitimate,
            'connection_frequency_past_week': connection_frequency,
            'detection_status': detection_status,
            'attack_details': {
                'detection_method': 'historical_as_relationship_validation_with_updates_verification',
                'as_rel_data_coverage': 'current_month',
                'updates_verification_window': '1_week',
                'data_source': 'merged_historical_files'
            },
        }
    
    raw_alerts = []
    for _, row in forge_df.iterrows():
        fake_connect = row.get('exact_fake_connect', '')
        key = (row['prefix'], fake_connect)
        group_info = group_results.get(key)
        if not group_info:
            continue
        row_dict = row.to_dict()
        row_dict.update({
            'type': 'mitm_hijack',
            'attack_type': 'mitm_hijack',
            'fake_connection': fake_connect,
            'victim_as': prefix_to_as.get(row['prefix'], victim_default or target_as or "unknown"),
            'hijacker_as': group_info.get('most_suspicious_hijacker'),
            'suspicious_hijacker': group_info.get('suspicious_hijacker', []),
            'risk_score': group_info.get('risk_score'),
            'confidence': group_info.get('confidence'),
            'detection_status': group_info.get('detection_status'),
            'connection_frequency_past_week': group_info.get('connection_frequency_past_week'),
            'first_seen': group_info.get('first_seen'),
            'last_seen': group_info.get('last_seen'),
            'announcement_count_group': group_info.get('announcement_count'),
            'attack_details': group_info.get('attack_details', {}),
        })
        raw_alerts.append(row_dict)
    
    legitimate_count = sum(1 for a in group_results.values() if a.get('is_legitimate', False))
    illegal_count = len(group_results) - legitimate_count
    
    logger.info(f"Detected {len(group_results)} potential MITM attacks (fake connections)")
    logger.info(f"  - Legitimate connections: {legitimate_count}")
    logger.info(f"  - Illegal connections: {illegal_count}")
    
    return raw_alerts


def save_alert_messages(target_as, start_time, end_time, mitm_alerts, origin_alerts):
    asn_clean = str(target_as).replace('AS', '').replace('as', '')
    time_str = start_time.strftime("%Y%m%d_%H%M%S")
    
    base_dir = Path("/data/bgp_tracer/results/hijack_detection")
    mitm_dir = base_dir / "mitm_df"
    origin_dir = base_dir / "origin_df"
    
    mitm_dir.mkdir(parents=True, exist_ok=True)
    origin_dir.mkdir(parents=True, exist_ok=True)
    
    if mitm_alerts:
        mitm_filename = f"AS{asn_clean}_{time_str}_mitm.txt"
        mitm_filepath = mitm_dir / mitm_filename
        
        with open(mitm_filepath, 'w', encoding='utf-8') as f:
            for alert in mitm_alerts:
                alert_json = json.dumps(alert, ensure_ascii=False, default=str)
                f.write(alert_json + '\n')
        
        logger.info(f"Saved {len(mitm_alerts)} MITM alerts to {mitm_filepath}")
    else:
        logger.info("No MITM alerts to save")
    
    if origin_alerts:
        origin_filename = f"AS{asn_clean}_{time_str}_origin.txt"
        origin_filepath = origin_dir / origin_filename
        
        with open(origin_filepath, 'w', encoding='utf-8') as f:
            for alert in origin_alerts:
                alert_json = json.dumps(alert, ensure_ascii=False, default=str)
                f.write(alert_json + '\n')
        
        logger.info(f"Saved {len(origin_alerts)} Origin alerts to {origin_filepath}")
    else:
        logger.info("No Origin alerts to save")


def detect_hijacks_streaming(
    start_time: datetime,
    end_time: datetime,
    target_as,  # Can be str or List[str]
    validate_with_updates: bool = False,
    save_alerts: bool = True,
    update_workers: int = 1,
    io_busy_threshold: int = 85,
):
    # Normalize input: convert to list of AS numbers
    if isinstance(target_as, str):
        target_as_list = [target_as]
    else:
        target_as_list = list(target_as)
    
    # Clean AS numbers (remove 'AS' prefix)
    cleaned_as_list = []
    for asn in target_as_list:
        asn_str = str(asn)
        if asn_str.startswith('AS') or asn_str.startswith('as'):
            asn_str = asn_str[2:]
        cleaned_as_list.append(asn_str)
    
    logger.info(f"Starting STREAMING hijack detection for AS{', '.join(cleaned_as_list)} from {start_time} to {end_time}")
    
    as_relationships_data = load_historical_as_relationships(start_time, months_back=0)
    
    prefix2as_path = process_prefix2as(start_time)
    if prefix2as_path:
        with open(prefix2as_path, 'r', encoding='utf-8') as f:
            prefix_to_as = json.load(f)
        logger.info(f"Loaded prefix-to-AS mappings from {prefix2as_path}")
    else:
        logger.error("Failed to load prefix-to-AS mappings")
        prefix_to_as = {}
    
    # Get prefixes for all target AS numbers
    prefixes_by_as = get_target_prefixes_batch(cleaned_as_list, prefix_to_as)
    # Union of all target prefixes for filtering
    union_target_prefixes = set().union(*prefixes_by_as.values()) if prefixes_by_as else set()
    cleaned_as_set = set(cleaned_as_list)
    
    # Initialize results for each AS
    results_by_as = {}
    for asn in cleaned_as_list:
        results_by_as[asn] = {
            'origin_hijacked': [],
            'forge_hijacked': [],
            'origin_hijacking': [],
            'forge_hijacking': [],
        }
    
    # Collect all fake connections across all chunks for batch validation
    all_fake_connection_groups = {}
    
    total_announcements = 0
    
    chunk_count = 0
    for df_chunk in get_updates_streaming(start_time, end_time, workers=update_workers, io_busy_threshold=io_busy_threshold):
        chunk_count += 1
        
        if df_chunk is None or df_chunk.empty:
            logger.info(f"Chunk {chunk_count} is empty, skipping")
            continue
        
        announcements = df_chunk[df_chunk['A/W'] == 'A']
        if announcements.empty:
            logger.info(f"Chunk {chunk_count} has no announcements, skipping")
            continue
        
        total_announcements += len(announcements)
        
        # Copy only if needed (check_fake_connections_in_df may modify inplace)
        announcements = announcements.copy()
        
        # Remove consecutive duplicates (apply is necessary here as it's a custom function)
        announcements['as-path'] = announcements['as-path'].apply(
            remove_consecutive_duplicates
        )
        
        # Extract origin-as efficiently using vectorized string operations
        announcements['origin-as'] = announcements['as-path'].str.split().str[-1]
        
        # Single fake connection check for entire chunk
        # Pass file paths for cache key based on monthly AS relationship files
        # Use ultra_fast mode for better performance with large datasets
        # Note: ultra_fast mode collects ALL fake connections (not just the first one)
        asrel_file_paths = as_relationships_data.get('_file_paths', None)
        announcements = check_fake_connections_in_df(
            announcements, 
            as_relationships_data,
            asrel_file_paths=asrel_file_paths,
            use_ultra_fast=True,  # Enable ultra-fast mode for trunk processing
            early_exit=False  # Collect ALL fake connections, not just the first one
        )
        logger.info(f"Chunk {chunk_count}: fake connection check completed")
        
        # Filter: keep only announcements related to any target AS
        # 1. Prefix belongs to any target AS (vectorized)
        prefix_match = announcements['prefix'].isin(union_target_prefixes)
        
        # 2. AS-path contains any target AS (vectorized)
        # Check if any target AS appears in the as-path
        as_path_contains_target = pd.Series([False] * len(announcements), index=announcements.index)
        for target_as in cleaned_as_list:
            as_path_contains_target |= announcements['as-path'].str.contains(target_as, na=False, regex=False)
        
        # Combine both conditions
        relevant_mask = prefix_match | as_path_contains_target
        announcements = announcements[relevant_mask]
        logger.info(f"Chunk {chunk_count}: filtering completed, {len(announcements)} relevant announcements")
        
        if announcements.empty:
            logger.info(f"Chunk {chunk_count}: no relevant announcements after filtering")
            del df_chunk, announcements
            if chunk_count % 10 == 0:
                gc.collect()
            continue
        
        # Process each AS separately from the filtered announcements
        for target_as in cleaned_as_list:
            target_prefixes = prefixes_by_as.get(target_as, set())
            
            # Filter announcements for this specific AS
            # 1. ip_related == True → This AS is being attacked (prefix belongs to this AS)
            related = announcements[announcements['prefix'].isin(target_prefixes)]
            
            if not related.empty:
                origin_hijacked_chunk = detect_origin_hijacks(related, prefix_to_as)
                results_by_as[target_as]['origin_hijacked'].extend(origin_hijacked_chunk)
                
                forge_hijacked_chunk = detect_forge_hijacks(
                    related,
                    as_relationships_data,
                    target_as,
                    prefix_to_as,
                    validate_with_updates=False,  # Batch validation later - collect all first
                    victim_default=target_as,
                )
                results_by_as[target_as]['forge_hijacked'].extend(forge_hijacked_chunk)
                
                # Collect fake connections for batch validation
                forge_df = related[related['has_fake_connect'] == True]
                for idx, frow in forge_df.iterrows():
                    fake_connect = frow.get('exact_fake_connect', '')
                    if fake_connect and not pd.isna(fake_connect):
                        key = (target_as, frow['prefix'], fake_connect)
                        if key not in all_fake_connection_groups:
                            all_fake_connection_groups[key] = {
                                'prefix': frow['prefix'],
                                'fake_connection': fake_connect,
                                'first_seen': str(frow['timestamp']),
                                'last_seen': str(frow['timestamp']),
                                'as_path': frow['as-path'],
                                'paths': [frow['as-path']],
                                'announcement_count': 1
                            }
                        else:
                            all_fake_connection_groups[key]['last_seen'] = max(
                                all_fake_connection_groups[key]['last_seen'],
                                str(frow['timestamp'])
                            )
                            all_fake_connection_groups[key]['announcement_count'] += 1
                            if frow['as-path'] not in all_fake_connection_groups[key]['paths']:
                                all_fake_connection_groups[key]['paths'].append(frow['as-path'])
            
            # 2. ip_related == False AND as_path contains target_as → This AS is attacking others
            not_related = announcements[~announcements['prefix'].isin(target_prefixes)]
            contain_target = not_related[
                not_related['as-path'].str.contains(target_as, na=False)
            ]
            
            if not contain_target.empty:
                origin_hijacking_chunk = detect_origin_hijacks(
                    contain_target, prefix_to_as
                )
                results_by_as[target_as]['origin_hijacking'].extend(origin_hijacking_chunk)
                
                forge_hijacking_chunk = detect_forge_hijacks(
                    contain_target,
                    as_relationships_data,
                    target_as,
                    prefix_to_as,
                    validate_with_updates=False,  # Batch validation later - collect all first
                    victim_default="unknown",
                    update_workers=update_workers,
                    io_busy_threshold=io_busy_threshold,
                )
                results_by_as[target_as]['forge_hijacking'].extend(forge_hijacking_chunk)
                
                # Collect fake connections for batch validation
                forge_df = contain_target[contain_target['has_fake_connect'] == True]
                for idx, frow in forge_df.iterrows():
                    fake_connect = frow.get('exact_fake_connect', '')
                    if fake_connect and not pd.isna(fake_connect):
                        key = (target_as, frow['prefix'], fake_connect)
                        if key not in all_fake_connection_groups:
                            all_fake_connection_groups[key] = {
                                'prefix': frow['prefix'],
                                'fake_connection': fake_connect,
                                'first_seen': str(frow['timestamp']),
                                'last_seen': str(frow['timestamp']),
                                'as_path': frow['as-path'],
                                'paths': [frow['as-path']],
                                'announcement_count': 1
                            }
                        else:
                            all_fake_connection_groups[key]['last_seen'] = max(
                                all_fake_connection_groups[key]['last_seen'],
                                str(frow['timestamp'])
                            )
                            all_fake_connection_groups[key]['announcement_count'] += 1
                            if frow['as-path'] not in all_fake_connection_groups[key]['paths']:
                                all_fake_connection_groups[key]['paths'].append(frow['as-path'])
        
        # 清理chunk相关的内存（减少gc调用频率以提高性能）
        try:
            del df_chunk, announcements, related, not_related, contain_target
        except NameError:
            pass
        
        try:
            del origin_hijacked_chunk, forge_hijacked_chunk
        except NameError:
            pass
        
        try:
            del origin_hijacking_chunk, forge_hijacking_chunk
        except NameError:
            pass
        
        # 每10个chunk才调用一次gc.collect()以减少开销
        if chunk_count % 10 == 0:
            gc.collect()
        
        logger.info(f"Chunk {chunk_count}: processing completed for {len(cleaned_as_list)} AS")
    
    # Batch validate all fake connections across all chunks (single pass through historical data)
    batch_connection_frequencies = {}
    if validate_with_updates and all_fake_connection_groups:
        logger.info(f"Batch validating {len(all_fake_connection_groups)} fake connections across all chunks...")
        # Convert to format expected by batch_check_connection_frequency
        anomaly_groups_for_validation = {}
        for key, group in all_fake_connection_groups.items():
            # Use (prefix, fake_connection) as key for validation
            validation_key = (group['prefix'], group['fake_connection'])
            if validation_key not in anomaly_groups_for_validation:
                anomaly_groups_for_validation[validation_key] = group
            else:
                # Merge if duplicate
                existing = anomaly_groups_for_validation[validation_key]
                existing['last_seen'] = max(existing['last_seen'], group['last_seen'])
                existing['announcement_count'] += group['announcement_count']
        
        batch_connection_frequencies = batch_check_connection_frequency(
            anomaly_groups_for_validation,
            validate_with_updates=True,
            update_workers=update_workers,
            io_busy_threshold=io_busy_threshold,
        )
        logger.info(f"Batch validation completed: {len(batch_connection_frequencies)} connections checked")
        
        # Map back to (asn, prefix, fake_connection) keys
        for key, group in all_fake_connection_groups.items():
            validation_key = (group['prefix'], group['fake_connection'])
            if validation_key in batch_connection_frequencies:
                batch_connection_frequencies[key] = batch_connection_frequencies[validation_key]
    
    # Re-validate forge hijacks with computed frequencies
    if validate_with_updates and batch_connection_frequencies:
        logger.info("Re-validating forge hijacks with batch-computed frequencies...")
        for target_as in cleaned_as_list:
            # Re-validate forge_hijacked and forge_hijacking with batch frequencies
            for alert in results_by_as[target_as]['forge_hijacked'] + results_by_as[target_as]['forge_hijacking']:
                fake_conn = alert.get('fake_connection', '')
                prefix = alert.get('prefix', '')
                if fake_conn and prefix:
                    key = (target_as, prefix, fake_conn)
                    frequency = batch_connection_frequencies.get(key, 0)
                    alert['connection_frequency_past_week'] = frequency
                    alert['is_legitimate'] = frequency >= 10
                    alert['detection_status'] = 'legitimate_connection' if frequency >= 10 else 'illegal_connection'
                    alert['risk_score'] = 0.2 if frequency >= 10 else 0.9
                    alert['confidence'] = 'low' if frequency >= 10 else 'high'
    
    asorg_path = process_asorg(start_time)
    
    # Aggregate results for each AS
    all_results = {}
    for target_as in cleaned_as_list:
        all_anomalies = (
            results_by_as[target_as]['origin_hijacked']
            + results_by_as[target_as]['forge_hijacked']
            + results_by_as[target_as]['origin_hijacking']
            + results_by_as[target_as]['forge_hijacking']
        )
        aggregated_alerts = aggregate_anomalies(all_anomalies)
        
        all_results[target_as] = {
            "success": True,
            "asn": target_as,
            "analysis_period": f"{start_time} to {end_time}",
            "origin_hijacked": results_by_as[target_as]['origin_hijacked'],
            "forge_hijacked": results_by_as[target_as]['forge_hijacked'],
            "origin_hijacking": results_by_as[target_as]['origin_hijacking'],
            "forge_hijacking": results_by_as[target_as]['forge_hijacking'],
            "all_anomalies": all_anomalies,
            "aggregated_alerts": aggregated_alerts,
            "prefix2as_file": prefix2as_path,
            "asorg_file": asorg_path,
            "target_prefixes": list(prefixes_by_as.get(target_as, set())),
            "total_announcements": total_announcements,
            "analysis_timestamp": datetime.now().isoformat(),
        }
        
        logger.info(
            f"AS{target_as} detection completed: "
            f"{len(results_by_as[target_as]['origin_hijacked'])} origin hijacked, "
            f"{len(results_by_as[target_as]['forge_hijacked'])} forge hijacked, "
            f"{len(results_by_as[target_as]['origin_hijacking'])} origin hijacking, "
            f"{len(results_by_as[target_as]['forge_hijacking'])} forge hijacking"
        )
        
        if save_alerts:
            save_alert_messages(
                target_as, 
                start_time, 
                end_time,
                results_by_as[target_as]['forge_hijacked'] + results_by_as[target_as]['forge_hijacking'], 
                results_by_as[target_as]['origin_hijacked'] + results_by_as[target_as]['origin_hijacking']
            )
    
    # If single AS, return single result for backward compatibility
    if len(cleaned_as_list) == 1:
        return all_results[cleaned_as_list[0]]
    
    # Return combined results
    return {
        "success": True,
        "asn_list": cleaned_as_list,
        "results_by_as": all_results,
        "total_announcements": total_announcements,
        "analysis_period": f"{start_time} to {end_time}",
        "analysis_timestamp": datetime.now().isoformat(),
    }


def detect_hijacks(
    start_time: datetime,
    end_time: datetime,
    target_as: str,
    use_streaming: bool = True,
    validate_with_updates: bool = False,
    save_alerts: bool = True,
    update_workers: int = 1,
    io_busy_threshold: int = 85,
):
    return detect_hijacks_streaming(
        start_time, 
        end_time, 
        target_as, 
        validate_with_updates=validate_with_updates,
        save_alerts=save_alerts,
        update_workers=update_workers,
        io_busy_threshold=io_busy_threshold,
    )


def detect_hijacks_batch(
    start_time: datetime,
    end_time: datetime,
    target_as_list: List[str],
    validate_with_updates: bool = False,
    save_alerts: bool = True,
    update_workers: int = 1,
    io_busy_threshold: int = 85,
) -> Dict[str, Any]:
    """
    Batch hijack detection for multiple AS numbers.
    
    Key optimization: Read BGP update data ONCE and check all AS simultaneously.
    
    Args:
        start_time: Start time for analysis
        end_time: End time for analysis
        target_as_list: List of AS numbers to analyze
        validate_with_updates: Whether to validate fake connections with past week data
        save_alerts: Whether to save alerts to files
    
    Returns:
        Dict mapping AS number to detection results
    """
    logger.info(f"Starting BATCH hijack detection for {len(target_as_list)} AS from {start_time} to {end_time}")
    
    # Clean AS numbers
    cleaned_as_list = []
    for asn in target_as_list:
        asn_clean = str(asn).replace('AS', '').replace('as', '')
        cleaned_as_list.append(asn_clean)
    
    logger.info(f"Target AS list: {', '.join(['AS' + asn for asn in cleaned_as_list])}")
    
    # Load common data (only once for all AS)
    as_relationships_data = load_historical_as_relationships(start_time, months_back=0)
    
    prefix2as_path = process_prefix2as(start_time)
    if prefix2as_path:
        with open(prefix2as_path, 'r', encoding='utf-8') as f:
            prefix_to_as = json.load(f)
        logger.info(f"Loaded prefix-to-AS mappings from {prefix2as_path}")
    else:
        logger.error("Failed to load prefix-to-AS mappings")
        prefix_to_as = {}
    
    # Get target prefixes for each AS
    prefixes_by_as = get_target_prefixes_batch(cleaned_as_list, prefix_to_as)
    union_target_prefixes = set().union(*prefixes_by_as.values()) if prefixes_by_as else set()
    cleaned_as_set = set(cleaned_as_list)

    # Map prefix -> owners (target AS list) for fast victim lookup
    prefix_owner_map = {}
    for asn, pref_set in prefixes_by_as.items():
        for p in pref_set:
            prefix_owner_map.setdefault(p, []).append(asn)
    
    # Log prefix counts
    for asn in cleaned_as_list:
        prefix_count = len(prefixes_by_as.get(asn, set()))
        logger.info(f"AS{asn}: {prefix_count} target prefixes")
    
    # Initialize result containers for each AS
    batch_results = {}
    for asn in cleaned_as_list:
        batch_results[asn] = {
            "origin_hijacked": [],
            "forge_hijacked": [],
            "origin_hijacking": [],
            "forge_hijacking": [],
            "total_announcements": 0,
            "fake_connection_groups": {}  # Collect fake connections for batch validation
        }
    
    # Collect all fake connections across all chunks and AS for batch validation
    all_fake_connection_groups = {}
    
    # Stream BGP updates - READ ONLY ONCE for all AS
    chunk_count = 0
    for df_chunk in get_updates_streaming(start_time, end_time):
        chunk_count += 1
        
        if df_chunk is None or df_chunk.empty:
            logger.info(f"Chunk {chunk_count} is empty, skipping")
            continue
        
        announcements = df_chunk[df_chunk['A/W'] == 'A']
        if announcements.empty:
            logger.info(f"Chunk {chunk_count} has no announcements, skipping")
            continue
        
        # Preprocess announcements once
        announcements = announcements.copy()
        announcements['as-path'] = announcements['as-path'].apply(remove_consecutive_duplicates)
        announcements['origin-as'] = announcements['as-path'].str.split().str[-1]

        # Pre-filter: keep only updates whose prefix belongs to any target AS OR as-path contains any target AS
        def _is_relevant(row):
            prefix = row.get('prefix', '')
            if prefix in union_target_prefixes:
                return True
            path = str(row.get('as-path', '')).split()
            return any(asn in cleaned_as_set for asn in path)

        announcements = announcements[announcements.apply(_is_relevant, axis=1)]
        if announcements.empty:
            logger.info(f"Chunk {chunk_count}: no relevant announcements after filtering")
            continue

        # Check fake connections once for the filtered announcements
        # Pass file paths for cache key based on monthly AS relationship files
        # Use ultra_fast mode for better performance with large datasets
        # Note: ultra_fast mode collects ALL fake connections (not just the first one)
        asrel_file_paths = as_relationships_data.get('_file_paths', None)
        announcements = check_fake_connections_in_df(
            announcements, 
            as_relationships_data,
            asrel_file_paths=asrel_file_paths,
            use_ultra_fast=True,  # Enable ultra-fast mode for batch processing
            early_exit=False  # Collect ALL fake connections, not just the first one
        )

        # Single pass: dispatch rows to each AS (victim+attacker combined)
        per_as_rows: Dict[str, List[Dict[str, Any]]] = {asn: [] for asn in cleaned_as_list}

        for _, row in announcements.iterrows():
            row_dict = row.to_dict()
            as_path_tokens = set(str(row_dict.get('as-path', '')).split())
            prefix = row_dict.get('prefix', '')

            # Victim role: prefix owned by target AS
            victim_asns = prefix_owner_map.get(prefix, [])
            for asn in victim_asns:
                rd = dict(row_dict)
                rd['ip_related'] = True
                per_as_rows[asn].append(rd)

            # Attacker/transit role: as-path contains target AS
            involved_asns = as_path_tokens & cleaned_as_set
            for asn in involved_asns:
                rd = dict(row_dict)
                rd['ip_related'] = False
                per_as_rows[asn].append(rd)

        # Process each AS once using the merged rows (victim+attacker)
        for asn, rows in per_as_rows.items():
            if not rows:
                continue

            df_asn = pd.DataFrame(rows)
            batch_results[asn]["total_announcements"] += len(df_asn)

            victim_df = df_asn[df_asn['ip_related'] == True]
            attacker_df = df_asn[df_asn['ip_related'] == False]

            if not victim_df.empty:
                origin_hijacked_chunk = detect_origin_hijacks(victim_df, prefix_to_as)
                batch_results[asn]["origin_hijacked"].extend(origin_hijacked_chunk)

            if not attacker_df.empty:
                origin_hijacking_chunk = detect_origin_hijacks(attacker_df, prefix_to_as)
                batch_results[asn]["origin_hijacking"].extend(origin_hijacking_chunk)

            # Single MITM per AS on combined data
            forge_chunk = detect_forge_hijacks(
                df_asn,
                as_relationships_data,
                asn,
                prefix_to_as,
                validate_with_updates=False,  # batch validation later
                victim_default=asn,
                update_workers=update_workers,
                io_busy_threshold=io_busy_threshold,
            )

            # Split forge results into victim/attacker buckets by ip_related flag in alert (if present)
            for alert in forge_chunk:
                if alert.get('ip_related', True):
                    batch_results[asn]["forge_hijacked"].append(alert)
                else:
                    batch_results[asn]["forge_hijacking"].append(alert)

            # Collect fake connection groups for batch validation (single pass)
            forge_df = df_asn[df_asn['has_fake_connect'] == True]
            for idx, frow in forge_df.iterrows():
                fake_connect = frow.get('exact_fake_connect', '')
                if fake_connect and not pd.isna(fake_connect):
                    key = (asn, frow['prefix'], fake_connect)
                    if key not in all_fake_connection_groups:
                        all_fake_connection_groups[key] = {
                            'prefix': frow['prefix'],
                            'fake_connection': fake_connect,
                            'first_seen': str(frow['timestamp']),
                            'last_seen': str(frow['timestamp']),
                            'as_path': frow['as-path'],
                            'paths': [frow['as-path']],
                            'announcement_count': 1
                        }
                    else:
                        all_fake_connection_groups[key]['last_seen'] = max(
                            all_fake_connection_groups[key]['last_seen'],
                            str(frow['timestamp'])
                        )
                        all_fake_connection_groups[key]['announcement_count'] += 1
                        if frow['as-path'] not in all_fake_connection_groups[key]['paths']:
                            all_fake_connection_groups[key]['paths'].append(frow['as-path'])
        
        # 清理chunk相关的内存（减少gc调用频率以提高性能）
        try:
            del df_chunk, announcements, per_as_rows
        except NameError:
            pass
        
        try:
            del victim_df, attacker_df, df_asn, forge_df, forge_chunk
        except NameError:
            pass
        
        try:
            del origin_hijacked_chunk, origin_hijacking_chunk
        except NameError:
            pass
        
        # 每10个chunk才调用一次gc.collect()以减少开销
        if chunk_count % 10 == 0:
            gc.collect()
        
        logger.info(f"Chunk {chunk_count}: Processed for {len(cleaned_as_list)} AS (prefiltered relevant announcements)")
    
    # Batch validate all fake connections across all AS and chunks (single pass through historical data)
    batch_connection_frequencies = {}
    if validate_with_updates and all_fake_connection_groups:
        logger.info(f"Batch validating {len(all_fake_connection_groups)} fake connections across all AS and chunks...")
        # Convert to format expected by batch_check_connection_frequency
        anomaly_groups_for_validation = {}
        for key, group in all_fake_connection_groups.items():
            # Use (prefix, fake_connection) as key for validation
            validation_key = (group['prefix'], group['fake_connection'])
            if validation_key not in anomaly_groups_for_validation:
                anomaly_groups_for_validation[validation_key] = group
            else:
                # Merge if duplicate
                existing = anomaly_groups_for_validation[validation_key]
                existing['last_seen'] = max(existing['last_seen'], group['last_seen'])
                existing['announcement_count'] += group['announcement_count']
        
        batch_connection_frequencies = batch_check_connection_frequency(
            anomaly_groups_for_validation,
                validate_with_updates=True,
                update_workers=update_workers,
                io_busy_threshold=io_busy_threshold,
        )
        logger.info(f"Batch validation completed: {len(batch_connection_frequencies)} connections checked")
        
        # Map back to (asn, prefix, fake_connection) keys
        for key, group in all_fake_connection_groups.items():
            validation_key = (group['prefix'], group['fake_connection'])
            if validation_key in batch_connection_frequencies:
                batch_connection_frequencies[key] = batch_connection_frequencies[validation_key]
    
    # Re-validate forge hijacks with computed frequencies
    if validate_with_updates and batch_connection_frequencies:
        logger.info("Re-validating forge hijacks with batch-computed frequencies...")
        # Re-process forge hijacks with validated frequencies
        for asn in cleaned_as_list:
            # Re-validate forge_hijacked and forge_hijacking with batch frequencies
            for alert in batch_results[asn]["forge_hijacked"] + batch_results[asn]["forge_hijacking"]:
                fake_conn = alert.get('fake_connection', '')
                prefix = alert.get('prefix', '')
                if fake_conn and prefix:
                    key = (asn, prefix, fake_conn)
                    frequency = batch_connection_frequencies.get(key, 0)
                    alert['connection_frequency_past_week'] = frequency
                    alert['is_legitimate'] = frequency >= 10
                    alert['detection_status'] = 'legitimate_connection' if frequency >= 10 else 'illegal_connection'
    
    # Generate final results for each AS
    asorg_path = process_asorg(start_time)
    
    final_results = {}
    for asn in cleaned_as_list:
        result_data = batch_results[asn]
        
        all_anomalies = (
            result_data["origin_hijacked"]
            + result_data["forge_hijacked"]
            + result_data["origin_hijacking"]
            + result_data["forge_hijacking"]
        )
        aggregated_alerts = aggregate_anomalies(all_anomalies)
        
        final_results[asn] = {
            "success": True,
            "asn": asn,
            "analysis_period": f"{start_time} to {end_time}",
            "origin_hijacked": result_data["origin_hijacked"],
            "forge_hijacked": result_data["forge_hijacked"],
            "origin_hijacking": result_data["origin_hijacking"],
            "forge_hijacking": result_data["forge_hijacking"],
            "all_anomalies": all_anomalies,
            "aggregated_alerts": aggregated_alerts,
            "prefix2as_file": prefix2as_path,
            "asorg_file": asorg_path,
            "target_prefixes": list(prefixes_by_as[asn]),
            "total_announcements": result_data["total_announcements"],
            "analysis_timestamp": datetime.now().isoformat(),
        }
        
        logger.info(f"AS{asn} Detection: {len(result_data['origin_hijacked'])} origin hijacked, "
                   f"{len(result_data['forge_hijacked'])} forge hijacked, "
                   f"{len(result_data['origin_hijacking'])} origin hijacking, "
                   f"{len(result_data['forge_hijacking'])} forge hijacking")
        
        # Save alerts if requested
        if save_alerts:
            save_alert_messages(
                asn,
                start_time,
                end_time,
                result_data["forge_hijacked"] + result_data["forge_hijacking"],
                result_data["origin_hijacked"] + result_data["origin_hijacking"]
            )
    
    logger.info(f"Batch detection completed for {len(cleaned_as_list)} AS")
    
    return {
        "success": True,
        "batch_mode": True,
        "as_count": len(cleaned_as_list),
        "results_by_as": final_results,
        "analysis_period": f"{start_time} to {end_time}",
        "analysis_timestamp": datetime.now().isoformat()
    }


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="BGP Hijack Detection Tool (Merged)")
    parser.add_argument("--asn", required=True, help="AS number to monitor")
    parser.add_argument("--start", required=True, help="Start time (YYYY-MM-DD HH:MM)")
    parser.add_argument("--end", required=True, help="End time (YYYY-MM-DD HH:MM)")
    
    args = parser.parse_args()
    
    try:
        start_dt = datetime.strptime(args.start, "%Y-%m-%d %H:%M")
        end_dt = datetime.strptime(args.end, "%Y-%m-%d %H:%M")
    except ValueError:
        logger.error("Invalid time format. Use YYYY-MM-DD HH:MM")
        sys.exit(1)
        
    results = detect_hijacks(
        start_dt, 
        end_dt, 
        args.asn, 
        use_streaming=True,
        validate_with_updates=False,
        save_alerts=True
    )
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"Detection results for AS{args.asn}")
    print(f"Period: {args.start} to {args.end}")
    print(f"{'='*60}")
    
    print(f"\n📊 Detection Summary:")
    print(f"  origin_hijacked:    {len(results['origin_hijacked'])}")
    print(f"  forge_hijacked:      {len(results['forge_hijacked'])}")
    print(f"  origin_hijacking:    {len(results['origin_hijacking'])}")
    print(f"  forge_hijacking:     {len(results['forge_hijacking'])}")
    print(f"  Total announcements: {results['total_announcements']}")
    print(f"  MITM detection:      {results.get('mitm_detection_enabled', False)}")
    
    output_dir = Path("/data/bgp_tracer/results/hijack_detecttion/json")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    asn_clean = args.asn.replace('AS', '').replace('as', '')
    json_file = output_dir / f"hijack_results_AS{asn_clean}_{timestamp}.json"
    
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(json_results, f, indent=2, ensure_ascii=False)
    
    print(f"Results saved to: {json_file}")
