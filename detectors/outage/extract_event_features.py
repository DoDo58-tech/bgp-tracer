import os
import logging
import re
import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict
import polars as pl

# Data directory: bgp_tracer/data/ instead of detectors/outage/data/
DATA_DIR = Path(__file__).parent.parent.parent / "data"
CSV_FILE = DATA_DIR / "traffic-outage-info.csv"
UPDATES_DIR = DATA_DIR / "updates_rrc00" / "decoded"
OUTPUT_DIR = DATA_DIR / "event_features"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# RIPE RIS download URL
RIPE_RIS_URL = "http://data.ris.ripe.net/rrc00/"

# Log directory: bgp_tracer/logs/
import sys as _sys
_sys.path.append(str(Path(__file__).parent.parent.parent))
from config import LOG_FILE
import csv
from typing import Dict, List, Optional, Set, Tuple
from ipaddress import ip_network

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
BASELINE_DAYS = 7
Z_SCORE_THRESHOLD = 3.0
BUCKET_MINUTES = 5
MAX_WORKERS = 32
USE_PROCESSES = True


def parse_as_list(as_string):
    if as_string is None or as_string == '' or (isinstance(as_string, str) and as_string.strip() == ''):
        return set()
    
    as_set = set()
    # CJK comma U+3001 is sometimes used as a separator in legacy data.
    parts = re.split(r'[,\s\u3001]+', str(as_string))
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
    if dt_string is None or dt_string == '' or (isinstance(dt_string, str) and dt_string.strip() == ''):
        raise ValueError("Empty datetime string")
    
    dt_string = str(dt_string).strip()
    
    formats = [
        "%Y/%m/%d %H:%M",
        "%Y-%m-%d %H:%M",
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M",
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(dt_string, fmt)
        except ValueError:
            continue
    
    try:
        return pl.Series([dt_string]).str.to_datetime()[0].to_pydatetime()
    except Exception as e:
        raise ValueError(f"cannot parse datetime: {dt_string}, error: {e}")


def download_and_decode(url, gz_path, txt_path):
    """Download a gz file and decode it to txt using bgpdump. Returns True on success."""
    try:
        import subprocess
        result = subprocess.run(
            ["wget", "-q", "-c", "-T", "120", "-O", str(gz_path), url],
            capture_output=True, timeout=150
        )
        if result.returncode != 0:
            return False
        if not gz_path.exists() or gz_path.stat().st_size < 100:
            return False
        # Decode with bgpdump. Use the proc as a context manager so the
        proc = subprocess.Popen(
            ["bgpdump", "-M", "-t", "change", str(gz_path)],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
        )
        written = 0
        try:
            with open(txt_path, 'w', encoding='utf-8') as out:
                assert proc.stdout is not None
                try:
                    for line in proc.stdout:
                        decoded = line.decode('utf-8', errors='ignore').strip()
                        if decoded:
                            out.write(decoded + '\n')
                            written += 1
                finally:
                    if proc.stdout is not None:
                        proc.stdout.close()
            retcode = proc.wait()
        except Exception:
            # Make sure we don't leak a running bgpdump if the consumer
            # raises before ``proc.wait()`` runs.
            if proc.poll() is None:
                try:
                    proc.kill()
                    proc.wait(timeout=5)
                except (ValueError):
                    pass
            raise
        if retcode != 0:
            return False
        return written > 0
    except (AttributeError) as e:
        logger.debug(f"Download/decode failed for {url}: {e}")
        return False


def find_update_files(time_start, time_end, auto_download=True):
    """Find local decoded BGP update files for the time range.
    If auto_download=True, missing files are downloaded from RIPE RIS and decoded."""
    import os as _os
    from concurrent.futures import ThreadPoolExecutor, as_completed

    files = []
    missing = []

    current = time_start
    while current <= time_end:
        minute = (current.minute // BUCKET_MINUTES) * BUCKET_MINUTES
        rounded_time = current.replace(minute=minute, second=0, microsecond=0)

        filename = f"updates.{rounded_time.strftime('%Y%m%d.%H%M')}.txt"
        filepath = UPDATES_DIR / filename

        if filepath.exists():
            files.append(filepath)
        else:
            missing.append((rounded_time, filepath))

        current += timedelta(minutes=BUCKET_MINUTES)

    if not missing or not auto_download:
        return sorted(files)

    # Auto-download missing files from RIPE RIS in parallel.
    logger.info(f"Auto-downloading {len(missing)} missing BGP update files from RIPE RIS...")
    workers = int(_os.environ.get("BGP_OUTAGE_DOWNLOAD_WORKERS", "8"))
    workers = max(1, min(workers, 16))

    def task(item):
        rounded_time, txt_path = item
        ym = rounded_time.strftime("%Y.%m")
        time_str = rounded_time.strftime("%Y%m%d.%H%M")
        url = f"{RIPE_RIS_URL}{ym}/updates.{time_str}.gz"
        gz_path = UPDATES_DIR / f"updates.{time_str}.gz"
        ok = download_and_decode(url, gz_path, txt_path)
        return (item, ok)

    downloaded = 0
    completed_files = []
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="outage-dl") as ex:
        futures = [ex.submit(task, m) for m in missing]
        for fut in as_completed(futures):
            try:
                (rounded_time, txt_path), ok = fut.result()
            except (AttributeError) as exc:
                logger.debug(f"download worker crashed: {exc}")
                continue
            if ok:
                completed_files.append(txt_path)
                downloaded += 1
                if downloaded % 10 == 0 or downloaded == len(missing):
                    logger.info(f"Outage baseline download: {downloaded}/{len(missing)}")

    files.extend(completed_files)
    logger.info(f"Downloaded and decoded {downloaded}/{len(missing)} files (workers={workers})")
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
        if not timestamp_str:
            return None
        timestamp = None
        # Try multiple timestamp formats (RIPE RIS decoded data uses MM/DD/YY).
        for fmt in (
            '%Y-%m-%d %H:%M:%S',  # ISO 2024-01-03 14:45:00
            '%Y-%m-%d %H:%M',
            '%Y-%m-%dT%H:%M:%S',  # ISO with T separator
            '%Y-%m-%dT%H:%M',     # ISO with T separator, no seconds
            '%m/%d/%y %H:%M:%S',  # RIPE RIS MM/DD/YY HH:MM:SS
            '%m/%d/%y %H:%M',
            '%m/%d/%Y %H:%M:%S',  # 4-digit year variant
            '%m/%d/%Y %H:%M',
        ):
            try:
                timestamp = datetime.strptime(timestamp_str, fmt)
                break
            except ValueError:
                continue
        if timestamp is None:
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
    if not as_path or as_path is None or (isinstance(as_path, str) and as_path.strip() == ''):
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


def extract_as_list(as_path):
    """Return the AS path as an *ordered* list of hops.

    ``extract_as_from_path`` returns a set, which is fine for a
    membership test but destroys two things the outage features need: the
    path length (a path may repeat a hop) and the origin (the last hop).
    This keeps the order.
    """
    if not as_path or as_path is None or (isinstance(as_path, str) and as_path.strip() == ''):
        return []

    as_path_clean = re.sub(r'\{[^}]+\}', '', as_path)
    hops = []
    for part in as_path_clean.split():
        part = part.strip()
        if not part:
            continue
        try:
            hops.append(int(part))
        except ValueError:
            continue
    return hops


def bucket_start(ts):
    minute = (ts.minute // BUCKET_MINUTES) * BUCKET_MINUTES
    return ts.replace(minute=minute, second=0, microsecond=0)


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
    # A bucket can hold withdrawals without any announcement, so the
    # denominator must be guarded explicitly: `dict.get(k, 1)` only helps
    # when the key is absent, and this key is always present.
    announcement_count = b.get('announcement_count', 0)
    rate_denominator = announcement_count if announcement_count else 1

    return {
        'announcement_count': announcement_count,
        'withdrawal_count': b.get('withdrawal_count', 0),
        'total_messages': b.get('total_messages', 0),
        'flapping_prefix_count': len(b.get('flapping_prefixes', set())),

        # Route hijacking/leakage core features
        'ori_change_rate': b.get('num_ori_change', 0) / rate_denominator,
        'num_ori_change': b.get('num_ori_change', 0),
        'path_change_rate': (b.get('num_longer', 0) + b.get('num_shorter', 0)) / rate_denominator,

        # BGP storm/abnormal behavior features
        'dup_A_rate': b.get('num_dup_A', 0) / rate_denominator,
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

        # Prefix-level features.  The multi-file merge reads these three
        # keys, so they have to be emitted here; without them the merge
        # raised KeyError and the prefix-disappearance feature was
        # permanently 0.
        'announced_prefix_count': len(b.get('announced_prefixes', set())),
        'withdrawn_prefix_count': len(b.get('withdrawn_prefixes', set())),
        'unique_prefix_count': len(b.get('unique_prefixes', set())),

        'origin_change_count': b.get('num_ori_change', 0),
    }


def _collect_owned_prefixes(file_path, target_as_set):
    """Prefixes the target AS originates in this file.

    A withdrawal carries no AS path, so attributing it to the victim
    requires knowing that the victim originated the prefix.  The MRT feed
    interleaves announcements and withdrawals from different peers, so
    the ownership has to be established for the whole file *before* the
    withdrawals are judged -- deciding it in stream order would miss
    every withdrawal that the feed happened to record before the
    matching announcement.
    """
    owned = set()
    with open(file_path, 'r', encoding='utf-8', errors='ignore', buffering=1024*1024) as f:
        for line in f:
            bgp_msg = parse_bgp_line(line)
            if not bgp_msg or not bgp_msg.get('as_path'):
                continue
            as_list = extract_as_list(bgp_msg['as_path'])
            if as_list and as_list[-1] in target_as_set:
                owned.add(bgp_msg['prefix'])
    return owned


def process_single_file_timeseries(file_path, target_as_list, prefix_to_target=None):
    target_as_set = set(target_as_list)
    buckets = {}
    # keep per-prefix state within this file for flapping
    prefix_history = defaultdict(list)
    # Track per-prefix routing state for new features
    prefix_routes = defaultdict(lambda: {'last_as_path': None, 'last_origin': None, 'announce_count': 0, 'withdraw_count': 0, 'had_withdraw': False})
    # A withdrawal record in the MRT feed carries no AS_PATH: it is
    # "peer X stopped announcing prefix P".  The only way to know that P
    # belongs to the target AS is to have seen P announced *by* the target
    # AS.  Without this map the relevance test below can only match a
    # withdrawal when the target AS is the collector's local AS, which hid
    # essentially every withdrawal of the victim's own routes -- the
    # defining physical signature of an outage.
    #
    # The map is carried *across* files: a route the victim announced
    # hours ago and withdraws now is still the victim's route.  Scoping
    # it to one file made every withdrawal that was not preceded by an
    # announcement in the same 5-minute bucket invisible, which is why
    # the withdrawal count was near zero on most windows.
    if prefix_to_target is None:
        prefix_to_target = {}
    # Ownership for this file is resolved up front so that a withdrawal
    # is judged against the whole file rather than against the stream
    # position it happens to sit at.
    file_owned = _collect_owned_prefixes(file_path, target_as_set)
    prefix_to_target.update({p: target_as_list[0] for p in file_owned})
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
                    as_list = extract_as_list(bgp_msg['as_path'])
                    if set(as_list) & target_as_set:
                        relevant = True
                    # The origin AS is the *last* hop of the path.  It has
                    # to be read from the ordered path, not from the set
                    # of hops (whose iteration order is arbitrary).
                    if as_list:
                        origin_hop = as_list[-1]
                        if origin_hop in target_as_set:
                            prefix_to_target[bgp_msg['prefix']] = origin_hop
                elif bgp_msg.get('type') == 'W' and bgp_msg['prefix'] in prefix_to_target:
                    # A withdrawal of a prefix the target AS was seen to
                    # originate.  It carries no path, so this is the only
                    # way to attribute it.
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
                        # The path as an ordered list of hops.  The
                        # *set* of hops is only usable for a membership
                        # test: it loses the path length (an AS path may
                        # repeat a hop) and it loses the origin, because
                        # a set has no order.  Both matter here -- the
                        # path length feeds the outage score and the
                        # origin decides whether the announcement is the
                        # target's own route.
                        as_list = extract_as_list(bgp_msg['as_path'])
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
    except (ValueError) as e:
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
    """Build the per-bucket feature series for one target AS.

    The files are processed in chronological order and share one
    ``prefix_to_target`` map, because attributing a withdrawal to the
    victim depends on having seen the victim's announcement of that
    prefix *earlier*.  A parallel implementation would make that
    attribution depend on the order the workers happened to finish in.

    This text path is the fallback for when the parquet cache is
    unavailable; the parquet path (``outage_features_parquet``) is the
    one that runs by default.
    """
    if not update_files:
        return {}
    results = {}
    files = sorted(str(p) for p in update_files)
    target_as_list = list(target_as_set)
    prefix_to_target: Dict[str, int] = {}

    for fp in files:
        part = process_single_file_timeseries(fp, target_as_list, prefix_to_target)
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
                n1 = results[ts].get('_weight', results[ts]['total_messages'])
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
    """Detect anomalies using multiple baseline periods.
    Uses mean and std computed across all baseline periods for each time slot.
    
    Returns:
    list of anomaly dicts with timestamp, feature, z_score, etc."""
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
            except (ValueError):
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
        
        event_features = aggregate_timeseries_to_totals(event_ts) if event_ts else {}
        
        baseline_samples = []
        if baseline_ts:
            baseline_features_full = aggregate_timeseries_to_totals(baseline_ts)
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
                except (ValueError):
                    row = {'timestamp': ts_str}
                row.update(features)
                csv_data.append(row)
            
            if csv_data:
                df_csv = pl.DataFrame(csv_data)
                df_csv = df_csv.with_columns([
                    pl.col('timestamp').str.to_datetime().alias('timestamp')
                ])
                df_csv = df_csv.sort('timestamp')
                df_csv = df_csv.with_columns([
                    pl.col('timestamp').dt.strftime('%Y-%m-%d %H:%M:%S').alias('timestamp')
                ])
                
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
                df_csv = df_csv.select(available_columns)
                
                csv_file = csv_output_dir / f"{event_name}_timeseries.csv"
                df_csv.write_csv(csv_file)
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
        
    except (AttributeError) as e:
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
    df = pl.read_csv(CSV_FILE)
    print(f"Found {len(df)} events")
    
    results = []
    for row in df.iter_rows(named=True):
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