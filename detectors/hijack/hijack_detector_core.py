import sys
import os
import re
import json
import ipaddress
from datetime import datetime, timedelta
from typing import List, Dict, Set, Tuple, Any, Optional

import pandas as pd
import requests

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger
from detectors.hijack.hijack_utils import check_fake_connections_single_row, build_as_pair_set
from config import ES_HOST, ES_INDEX_NAME, USE_ES_FOR_CONN_FREQ, ES_CONN_FREQ_TIMEOUT, DEFAULT_FORGE_THRESHOLD


class ParentPrefixTrie:
    """Optimized trie structure for finding parent prefixes efficiently."""
    def __init__(self):
        self.ipv4_root = {}
        self.ipv6_root = {}
        self.ipv4_prefixes = {}  # prefix_str -> (network, origins)
        self.ipv6_prefixes = {}   # prefix_str -> (network, origins)
        self.cache = {}  # target_prefix -> (parent_prefix, origins)
        self.cache_hits = 0
        self.cache_misses = 0

    def insert(self, prefix_str, origins):
        """Insert a prefix into the trie."""
        try:
            network = ipaddress.ip_network(prefix_str, strict=False)
            version = network.version
            
            if version == 4:
                self.ipv4_prefixes[prefix_str] = (network, origins)
                self._insert_into_trie(self.ipv4_root, network, prefix_str, origins)
            else:  # IPv6
                self.ipv6_prefixes[prefix_str] = (network, origins)
                self._insert_into_trie(self.ipv6_root, network, prefix_str, origins)
        except Exception as e:
            logger.warning(f"Failed to insert prefix {prefix_str}: {e}")

    def _insert_into_trie(self, root, network, prefix_str, origins):
        """Insert a network into the trie structure.
        
        We store prefix info at each node along the path so that during lookup,
        we can find all possible parent prefixes efficiently.
        """
        ip_int = int(network.network_address)
        prefixlen = network.prefixlen
        
        if network.version == 4:
            binary = format(ip_int, '032b')
        else:
            binary = format(ip_int, '0128b')
        
        current = root
        # Store prefix at each node along the path (for parent lookup)
        for i in range(prefixlen):
            bit = int(binary[i])
            if bit not in current:
                current[bit] = {}
            current = current[bit]
            
            # Store prefix info at each node along the path
            # This allows us to find parent prefixes during lookup
            if 'prefixes' not in current:
                current['prefixes'] = []
            current['prefixes'].append((prefixlen, prefix_str, origins))
        
        # Also mark the end node
        if 'prefixes' not in current:
            current['prefixes'] = []
        if (prefixlen, prefix_str, origins) not in current['prefixes']:
            current['prefixes'].append((prefixlen, prefix_str, origins))

    def find_parent(self, target_prefix):
        """Find the most specific parent prefix using trie lookup."""
        # Check cache first
        if target_prefix in self.cache:
            self.cache_hits += 1
            return self.cache[target_prefix]
        
        self.cache_misses += 1
        
        try:
            target_network = ipaddress.ip_network(target_prefix, strict=False)
            version = target_network.version
            
            # Select appropriate trie
            root = self.ipv4_root if version == 4 else self.ipv6_root
            
            # Traverse trie to find longest matching parent
            ip_int = int(target_network.network_address)
            if version == 4:
                binary = format(ip_int, '032b')
            else:
                binary = format(ip_int, '0128b')
            
            current = root
            best_match = None
            best_prefixlen = -1
            
            # Traverse the trie, checking all nodes along the path for parent prefixes
            for i in range(target_network.prefixlen):
                # Check prefixes stored at current node before moving deeper
                if 'prefixes' in current:
                    for prefixlen, prefix_str, origins in current['prefixes']:
                        # Only consider prefixes that are shorter (parents) than target
                        if prefixlen < target_network.prefixlen:
                            stored_network, _ = (self.ipv4_prefixes if version == 4 else self.ipv6_prefixes)[prefix_str]
                            if stored_network.supernet_of(target_network) and prefixlen > best_prefixlen:
                                # Found a valid parent, track the longest (most specific) one
                                best_match = (prefix_str, origins)
                                best_prefixlen = prefixlen
                
                # Move to next level
                bit = int(binary[i])
                if bit not in current:
                    break
                current = current[bit]
            
            # Also check the final node we reached
            if 'prefixes' in current:
                for prefixlen, prefix_str, origins in current['prefixes']:
                    if prefixlen < target_network.prefixlen:
                        stored_network, _ = (self.ipv4_prefixes if version == 4 else self.ipv6_prefixes)[prefix_str]
                        if stored_network.supernet_of(target_network) and prefixlen > best_prefixlen:
                            best_match = (prefix_str, origins)
                            best_prefixlen = prefixlen
            
            result = best_match if best_match else (None, None)
            
            # Cache the result (limit cache size to prevent memory bloat)
            if len(self.cache) < 100000:
                self.cache[target_prefix] = result
            
            return result
            
        except Exception as e:
            logger.debug(f"Error in parent prefix lookup for {target_prefix}: {e}")
            return None, None

    def get_stats(self):
        """Get statistics about the trie."""
        return {
            'ipv4_prefixes': len(self.ipv4_prefixes),
            'ipv6_prefixes': len(self.ipv6_prefixes),
            'cache_size': len(self.cache),
            'cache_hits': self.cache_hits,
            'cache_misses': self.cache_misses,
            'cache_hit_rate': self.cache_hits / (self.cache_hits + self.cache_misses) if (self.cache_hits + self.cache_misses) > 0 else 0
        }


def build_optimized_prefix_lookup(prefix_to_as):
    """Build an optimized prefix lookup structure using trie."""
    logger.info("Building optimized prefix lookup structure for efficient sub-prefix hijack detection...")
    
    trie = ParentPrefixTrie()
    valid_count = 0
    invalid_count = 0
    
    for prefix_str, origins in prefix_to_as.items():
        try:
            network = ipaddress.ip_network(prefix_str, strict=False)
            trie.insert(prefix_str, origins)
            valid_count += 1
        except Exception as e:
            logger.warning(f"Invalid prefix format: {prefix_str} - {e}")
            invalid_count += 1
            continue
    
    stats = trie.get_stats()
    logger.info(f"Built optimized prefix lookup: {valid_count} valid prefixes "
                f"({stats['ipv4_prefixes']} IPv4, {stats['ipv6_prefixes']} IPv6)")
    if invalid_count > 0:
        logger.warning(f"Skipped {invalid_count} invalid prefixes")
    
    return trie


def find_parent_prefix_optimized(target_prefix, trie):
    """Find parent prefix using optimized trie lookup."""
    if isinstance(trie, ParentPrefixTrie):
        return trie.find_parent(target_prefix)
    else:
        # Fallback for old format (list-based)
        try:
            target_network = ipaddress.ip_network(target_prefix, strict=False)
            target_version = target_network.version
            
            for parent_network, parent_prefix, origins in trie:
                # Skip if version mismatch
                if parent_network.version != target_version:
                    continue
                if parent_network.supernet_of(target_network):
                    return parent_prefix, origins
            return None, None
        except Exception as e:
            logger.debug(f"Error in parent prefix lookup for {target_prefix}: {e}")
            return None, None


def check_origin_hijack_vectorized(row, prefix_to_as, target_as=None):
    """
    Check if a BGP announcement is an origin hijack.
    
    For origin_hijacked events (where our target AS is the victim):
    - The prefix being announced belongs to target_as
    - The origin_as (hijacker) is NOT target_as
    - victim_as = target_as
    
    Args:
        row: DataFrame row with prefix, as-path, timestamp
        prefix_to_as: Dict mapping prefixes to legitimate origin ASes
        target_as: The AS being analyzed (the potential victim)
    """
    try:
        prefix = row.get('prefix', '')
        as_path = row.get('as-path', '')
        timestamp = row.get('timestamp', '')

        if not prefix or not as_path:
            return None

        legitimate_origins = None
        checked_prefix = prefix

        if prefix in prefix_to_as:
            legitimate_origins = prefix_to_as[prefix]
        else:
            # Sub-prefix hijack detection: find parent prefix using optimized trie lookup
            if not hasattr(check_origin_hijack_vectorized, 'prefix_trie'):
                check_origin_hijack_vectorized.prefix_trie = build_optimized_prefix_lookup(prefix_to_as)

            parent_prefix, origins = find_parent_prefix_optimized(prefix, check_origin_hijack_vectorized.prefix_trie)

            if parent_prefix:
                legitimate_origins = origins
                checked_prefix = parent_prefix

        if not legitimate_origins:
            return None

        path_parts = as_path.strip().split()
        if not path_parts:
            return None

        origin_as = path_parts[-1]
        if not origin_as:
            return None

        if origin_as in legitimate_origins:
            return None
        
        # Determine hijack type and victim:
        # If target_as is in legitimate_origins (or is the only origin), then target_as is the victim
        # and origin_as is the hijacker. This is origin_hijacked.
        # 
        # If origin_as is target_as but the prefix doesn't belong to target_as, 
        # then target_as is the hijacker. This is origin_hijacking.
        
        # Convert target_as to string for comparison
        target_as_str = str(target_as) if target_as is not None else None
        legitimate_origins_str = [str(a) for a in legitimate_origins]
        
        # Check if target_as is a legitimate origin for this prefix
        is_target_legitimate = target_as_str in legitimate_origins_str if target_as_str else False
        
        if is_target_legitimate and str(origin_as) != target_as_str:
            # Target AS legitimately owns this prefix, but someone else announced it
            # This is origin_hijacked - our target is the victim
            hijacker_as = origin_as
            hijacker_as_list = [origin_as]
            victim_as = target_as
            victim_ases = [target_as] + [a for a in legitimate_origins if str(a) != target_as_str]
            hijack_type = 'origin_hijacked'
        elif str(origin_as) == target_as_str and not is_target_legitimate:
            # Origin is target_as, but this prefix doesn't belong to target_as
            # This is origin_hijacking - our target is attacking others
            hijacker_as = target_as
            hijacker_as_list = [target_as]
            victim_as = legitimate_origins[0] if legitimate_origins else None
            victim_ases = list(legitimate_origins)
            hijack_type = 'origin_hijacking'
        else:
            # Other cases: origin_as is legitimate owner, or origin belongs to target
            # This is NOT a hijack, it's legitimate traffic
            return None
        
        return {
            'hijack_type': hijack_type,
            'type': hijack_type,  # Use same type for consistency
            'timestamp': timestamp,
            'prefix': prefix,
            'checked_prefix': checked_prefix,
            'origin_as': origin_as,
            'legitimate_origins': legitimate_origins,
            'as_path': as_path,
            'hijacker_as': hijacker_as,
            'hijacker_as_list': hijacker_as_list,
            'victim_as': victim_as,
            'victim_ases': victim_ases,
            'expected_origin': victim_as,
            'target_as': target_as,  # Store target AS for reference
        }

    except Exception as e:
        logger.warning(f"Error in origin hijack check: {e}")
        return None


def detect_origin_hijacks(announcements, prefix_to_as, target_as=None):
    """
    Detect origin hijacks where an AS announces a prefix it doesn't own.
    
    Args:
        announcements: DataFrame of BGP announcements
        prefix_to_as: Dict mapping prefixes to their legitimate origin ASes
        target_as: The AS being analyzed (this is the victim in origin_hijacked events)
                   For origin_hijacked events, the victim is target_as.
                   For origin_hijacking events, the attacker is target_as.
    """
    try:
        if announcements.empty:
            logger.warning("No announcements to analyze for origin hijacks")
            return []

        logger.info(f"Analyzing {len(announcements)} announcements for origin hijacks")

        hijack_alerts = []
        for idx, row in announcements.iterrows():
            hijack_info = check_origin_hijack_vectorized(row, prefix_to_as, target_as)
            if hijack_info:
                hijack_alerts.append(hijack_info)

        logger.info(f"Detected {len(hijack_alerts)} origin hijacks")
        
        # Log trie performance statistics if available
        if hasattr(check_origin_hijack_vectorized, 'prefix_trie'):
            stats = check_origin_hijack_vectorized.prefix_trie.get_stats()
            logger.info(f"Prefix trie stats: cache_hit_rate={stats['cache_hit_rate']:.2%}, "
                       f"cache_size={stats['cache_size']}, "
                       f"hits={stats['cache_hits']}, misses={stats['cache_misses']}")
        
        return hijack_alerts

    except Exception as e:
        logger.error(f"Error detecting origin hijacks: {e}")
        return []


def batch_check_connection_frequency(updates_df, as_relationships,
                                   target_as, fake_conn_cache_manager, full_day_data=None):
    """
    Optimized batch connection frequency check with AS pair deduplication.
    Key optimization: Collect all unique fake AS pairs first, then batch query ES once.
    """
    try:
        if updates_df.empty:
            return updates_df

        logger.info(f"Checking connection frequency for {len(updates_df)} updates")

        as_pairs = build_as_pair_set(as_relationships)

        # Ensure date column exists
        if 'date' not in updates_df.columns:
            updates_df = updates_df.copy()
            # Handle multiple datetime formats including ISO with timezone (e.g., 2025-01-02T20:30:07+00:00Z)
            try:
                updates_df['date'] = pd.to_datetime(updates_df['timestamp'], format='ISO8601', errors='raise').dt.date.astype(str)
            except (ValueError, TypeError):
                try:
                    updates_df['date'] = pd.to_datetime(updates_df['timestamp'], errors='coerce').dt.date.astype(str)
                except Exception:
                    # Last resort: extract date string directly
                    updates_df['date'] = updates_df['timestamp'].astype(str).str[:10]

        # ========== PHASE 1: Collect all fake AS pairs from all updates (with deduplication) ==========
        # This avoids repeated ES queries for the same AS pair
        all_fake_pairs: Dict[str, Dict] = {}  # conn_key -> {as1, as2, timestamps: []}

        # Determine if we have cache manager
        has_cache = fake_conn_cache_manager is not None

        if has_cache:
            from detectors.hijack.hijack_cache_manager import get_asrel_hash, get_cached_as_pair, set_cached_as_pair
            asrel_hash = get_asrel_hash(as_relationships)
        else:
            asrel_hash = None

        # Vectorized approach: extract all AS paths and process in batch
        as_paths = updates_df['as-path'].fillna('').astype(str).tolist()
        dates = updates_df['date'].tolist()
        timestamps_col = updates_df['timestamp'].tolist()
        indices = updates_df.index.tolist()

        # First pass: identify all fake connections with their metadata
        for idx, (as_path_str, date_str, ts) in zip(indices, zip(as_paths, dates, timestamps_col)):
            as_path_list = as_path_str.split()
            for i in range(len(as_path_list) - 1):
                as1, as2 = as_path_list[i], as_path_list[i + 1]
                conn_key = f"{as1}|{as2}"

                if has_cache:
                    # Check AS pair cache (is this connection valid in AS relationships?)
                    cached_pair = get_cached_as_pair(as1, as2, date_str, asrel_hash)
                    if cached_pair is not None:
                        is_fake = cached_pair['is_fake']
                    else:
                        is_fake = (as1, as2) not in as_pairs
                        set_cached_as_pair(as1, as2, date_str, asrel_hash, is_fake, date_str)
                else:
                    # No cache manager - just check directly
                    is_fake = (as1, as2) not in as_pairs

                if is_fake:
                    if conn_key not in all_fake_pairs:
                        all_fake_pairs[conn_key] = {
                            'as1': as1,
                            'as2': as2,
                            'update_indices': [],
                            'dates': set(),
                            'timestamps': []
                        }
                    all_fake_pairs[conn_key]['update_indices'].append(idx)
                    all_fake_pairs[conn_key]['dates'].add(date_str)
                    all_fake_pairs[conn_key]['timestamps'].append(ts)

        logger.info(f"Found {len(all_fake_pairs)} unique fake AS pairs to analyze (deduplicated from updates)")

        if not all_fake_pairs:
            # No fake connections found - mark all as normal and return
            updates_df['connection_frequency_suspicious'] = False
            updates_df['has_fake_connect'] = False
            updates_df['fake_connections'] = '[]'
            logger.info("No fake AS pairs detected in any updates")
            return updates_df

        # ========== PHASE 2: Batch query ES for each unique fake pair (with caching) ==========
        frequency_results: Dict[str, Dict] = {}  # conn_key -> frequency_data

        for conn_key, pair_data in all_fake_pairs.items():
            # Use the most common date or latest timestamp for this pair
            dates = list(pair_data['dates'])
            date_str = dates[0] if dates else ''

            if has_cache:
                # Check if cached
                if fake_conn_cache_manager.is_fake_conn_cached(conn_key, date_str):
                    cached_result = fake_conn_cache_manager.get_cached_fake_conn_frequency(conn_key, date_str)
                    frequency_results[conn_key] = cached_result
                    continue

            # Query ES for frequency
            # Use the latest timestamp from this pair's updates
            end_ts = pair_data['timestamps'][-1] if pair_data['timestamps'] else date_str
            frequency_data = analyze_connection_frequency(
                conn_key,
                date_str,
                full_day_data if full_day_data is not None else updates_df,
                end_timestamp=end_ts,
            )

            if has_cache:
                # Cache the result
                fake_conn_cache_manager.set_cached_fake_conn_frequency(conn_key, date_str, frequency_data)

            frequency_results[conn_key] = frequency_data

        # ========== PHASE 3: Mark suspicious updates based on pre-computed results ==========
        suspicious_updates = []

        for conn_key, pair_data in all_fake_pairs.items():
            freq_data = frequency_results.get(conn_key, {})
            is_suspicious = freq_data.get('is_suspicious', False)

            if is_suspicious:
                suspicious_updates.extend(pair_data['update_indices'])

        # Remove duplicates (same update may have multiple fake pairs)
        suspicious_updates = list(set(suspicious_updates))

        # Apply results to DataFrame
        updates_df['connection_frequency_suspicious'] = False
        updates_df['has_fake_connect'] = False
        updates_df['fake_connections'] = '[]'

        # Mark updates that have fake connections
        for conn_key, pair_data in all_fake_pairs.items():
            for idx in pair_data['update_indices']:
                updates_df.at[idx, 'has_fake_connect'] = True
                # Also store the fake connection info
                fake_conn_info = [{
                    'as1': pair_data['as1'],
                    'as2': pair_data['as2'],
                    'path': updates_df.at[idx, 'as-path'],
                    'timestamp': updates_df.at[idx, 'timestamp']
                }]
                updates_df.at[idx, 'fake_connections'] = json.dumps(fake_conn_info)

        if suspicious_updates:
            updates_df.loc[suspicious_updates, 'connection_frequency_suspicious'] = True
            logger.info(f"Marked {len(suspicious_updates)} updates as suspicious based on connection frequency")

        return updates_df

    except Exception as e:
        logger.error(f"Error in batch connection frequency check: {e}")
        import traceback
        traceback.print_exc()
        updates_df['connection_frequency_suspicious'] = False
        return updates_df


def calculate_adaptive_threshold(updates_df, fake_connection, date_str):
    try:
        if updates_df is None or updates_df.empty:
            return DEFAULT_FORGE_THRESHOLD

        date_updates = updates_df[updates_df['date'] == date_str]
        if date_updates.empty:
            return DEFAULT_FORGE_THRESHOLD

        total_updates = len(date_updates)

        try:
            as1, as2 = fake_connection.split('|')
            target_as = as1 if as1.isdigit() else as2
        except:
            return DEFAULT_FORGE_THRESHOLD

        as_activity_count = 0
        if 'as-path' in date_updates.columns:
            for as_path in date_updates['as-path'].fillna(''):
                if str(target_as) in str(as_path):
                    as_activity_count += 1

        activity_ratio = as_activity_count / total_updates if total_updates > 0 else 0

        if activity_ratio >= 0.1:
            threshold = 0.0005
        elif activity_ratio >= 0.01:
            threshold = DEFAULT_FORGE_THRESHOLD
        elif activity_ratio >= 0.001:
            threshold = 0.002
        else:
            threshold = 0.005

        threshold = max(0.0001, min(threshold, 0.01))

        return threshold

    except Exception as e:
        logger.warning(f"Error calculating adaptive threshold: {e}")
        return DEFAULT_FORGE_THRESHOLD


def _parse_timestamp_for_es(end_timestamp: Optional[str], fallback_date: str) -> datetime:
    """
    Parse the given timestamp string (which may be in various ISO-like formats)
    and return a datetime object. If parsing fails, fall back to the provided date.
    """
    if end_timestamp:
        # 清理时间戳：移除Z，标准化时区格式
        ts = end_timestamp.strip()
        if ts.endswith('Z'):
            ts = ts[:-1] + '+0000'
        # 处理 +00:00 格式
        if '+00:00' in ts:
            ts = ts.replace('+00:00', '+0000')
        
        # 支持多种格式
        formats = [
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S+0000",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d"
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(ts, fmt)
            except Exception:
                continue
        
        # 最后尝试dateutil解析器
        try:
            from dateutil import parser
            return parser.parse(ts)
        except ImportError:
            pass
    
    # Fallback to date-only parsing
    try:
        return datetime.strptime(fallback_date, "%Y-%m-%d")
    except Exception:
        return datetime.utcnow()


def _query_es_connection_frequency(fake_connection: str, end_timestamp: Optional[str], date_str: str) -> Optional[Dict[str, Any]]:
    """
    Query Elasticsearch for the frequency of a fake connection in the past 7 days.

    Returns a dict shaped like the original analyze_connection_frequency result,
    or None if ES is disabled/unavailable/failed.
    """
    try:
        if not (USE_ES_FOR_CONN_FREQ and ES_HOST and ES_INDEX_NAME):
            return None

        end_dt = _parse_timestamp_for_es(end_timestamp, date_str)
        start_dt = end_dt - timedelta(days=7)

        logger.info(
            "[ES] Querying Elasticsearch for AS pair frequency: %s (7-day window %s to %s)",
            fake_connection, start_dt.strftime("%Y-%m-%d"), end_dt.strftime("%Y-%m-%d")
        )
        es_url = ES_HOST.rstrip("/") + f"/{ES_INDEX_NAME}"
        logger.info("[ES] Target index: %s", es_url)

        # Count documents containing this AS pair within the 7-day window
        query = {
            "query": {
                "bool": {
                    "filter": [
                        {
                            "range": {
                                "timestamp": {
                                    "gte": start_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                    "lte": end_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                }
                            }
                        },
                        {"term": {"as_pairs": fake_connection}},
                    ]
                }
            }
        }

        resp = requests.post(f"{es_url}/_count", json=query, timeout=ES_CONN_FREQ_TIMEOUT)
        if resp.status_code != 200:
            logger.warning(f"ES frequency query failed ({resp.status_code}): {resp.text[:200]}")
            return None

        data = resp.json()
        conn_count = int(data.get("count", 0))

        # Also get total BGP messages in the same period for context
        total_query = {
            "query": {
                "range": {
                    "timestamp": {
                        "gte": start_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "lte": end_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    }
                }
            }
        }
        total_resp = requests.post(f"{es_url}/_count", json=total_query, timeout=ES_CONN_FREQ_TIMEOUT)
        total = 0
        if total_resp.status_code == 200:
            total = int(total_resp.json().get("count", 0))

        # If ES returns no data for this time window, return None to trigger fallback
        if total == 0:
            logger.info(f"ES has no data for time range {start_dt.date()} to {end_dt.date()}, falling back to local data")
            return None

        frequency_ratio = (conn_count / total) if total > 0 else 0.0

        # For ES-based statistics, use a simple conservative threshold:
        # treat connections with extremely low frequency as suspicious.
        threshold_used = DEFAULT_FORGE_THRESHOLD
        is_suspicious = frequency_ratio <= threshold_used

        return {
            "connection": fake_connection,
            "date": date_str,
            "count": conn_count,
            "total_updates": total,
            "frequency_ratio": frequency_ratio,
            "is_suspicious": is_suspicious,
            "threshold_used": threshold_used,
            "threshold_percentage": threshold_used * 100,
            "data_coverage": "es_7d_window",
            "analysis_quality": "es_based",
            "note": (
                f"ES 7-day window [{start_dt.isoformat()} to {end_dt.isoformat()}], "
                f"count={conn_count}, total={total}"
            ),
            "analysis_timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        logger.warning(f"Error querying ES for connection frequency ({fake_connection}): {e}")
        return None


def analyze_connection_frequency(fake_connection, date_str, updates_df, end_timestamp: Optional[str] = None):
    try:
        # Preferred path: use Elasticsearch for the last 7 days, if enabled and available
        es_result = _query_es_connection_frequency(fake_connection, end_timestamp, date_str)
        if es_result is not None:
            logger.info(
                "[ES] Using ES result for AS pair %s: count=%s, total=%s, ratio=%.4f, suspicious=%s",
                fake_connection,
                es_result.get("count", 0),
                es_result.get("total_updates", 0),
                es_result.get("frequency_ratio", 0.0),
                es_result.get("is_suspicious", False),
            )
            return es_result

        # Fallback to local MRT/updates-based statistics when ES is disabled/unreachable
        if updates_df is None or updates_df.empty:
            return {
                'connection': fake_connection,
                'date': date_str,
                'count': 0,
                'total_updates': 0,
                'frequency_ratio': 0.0,
                'is_suspicious': True,
                'note': 'No BGP data available for frequency analysis',
                'data_coverage': 'unavailable',
                'analysis_timestamp': datetime.now().isoformat()
            }

        # Ensure date column exists
        if 'date' not in updates_df.columns:
            updates_df = updates_df.copy()
            # Handle multiple datetime formats including ISO with timezone
            try:
                updates_df['date'] = pd.to_datetime(updates_df['timestamp'], format='ISO8601', errors='raise').dt.date.astype(str)
            except (ValueError, TypeError):
                try:
                    updates_df['date'] = pd.to_datetime(updates_df['timestamp'], errors='coerce').dt.date.astype(str)
                except Exception:
                    updates_df['date'] = updates_df['timestamp'].astype(str).str[:10]

        # Try to get more data by using 7-day window from the provided data
        # Parse end_timestamp to determine the time window
        end_dt = None
        if end_timestamp:
            try:
                end_dt = datetime.strptime(end_timestamp[:19].replace('Z', ''), "%Y-%m-%dT%H:%M:%S")
            except:
                try:
                    end_dt = datetime.strptime(end_timestamp[:10], "%Y-%m-%d")
                except:
                    pass

        if end_dt:
            start_dt = end_dt - timedelta(days=7)
            # Filter to 7-day window
            window_updates = updates_df[
                (pd.to_datetime(updates_df['timestamp'], errors='coerce') >= start_dt) &
                (pd.to_datetime(updates_df['timestamp'], errors='coerce') <= end_dt)
            ]
            if not window_updates.empty:
                logger.debug(f"Using 7-day window data: {len(window_updates)} updates")
                date_updates = window_updates
                data_source = '7d_window'
            else:
                # Fallback to specific date
                date_updates = updates_df[updates_df['date'] == date_str]
                data_source = 'single_day'
        else:
            # Default: use provided updates (could be full day data)
            date_updates = updates_df[updates_df['date'] == date_str]
            data_source = 'single_day'

        if date_updates.empty:
            return {
                'connection': fake_connection,
                'date': date_str,
                'count': 0,
                'total_updates': 0,
                'frequency_ratio': 0.0,
                'is_suspicious': True,
                'note': f'No BGP data available for date {date_str}',
                'data_coverage': 'insufficient',
                'analysis_timestamp': datetime.now().isoformat()
            }

        # Get AS path column - use vectorized string operations (faster than loop)
        if 'as_path' in date_updates.columns:
            as_path_series = date_updates['as_path'].fillna('').astype(str)
        elif 'as-path' in date_updates.columns:
            as_path_series = date_updates['as-path'].fillna('').astype(str)
        else:
            as_path_series = pd.Series([''] * len(date_updates), index=date_updates.index)

        # Count occurrences using vectorized approach (much faster than loop)
        connection_count = as_path_series.str.contains(fake_connection, regex=False).sum()

        total_updates = len(date_updates)
        frequency_ratio = connection_count / total_updates if total_updates > 0 else 0

        # Dynamic threshold based on AS activity level
        # Calculate threshold based on the AS's activity in the full day data
        threshold_used = calculate_adaptive_threshold(updates_df, fake_connection, date_str)
        is_suspicious = frequency_ratio <= threshold_used

        # Get data source info for logging
        data_source_info = data_source if 'data_source' in dir() else 'full_day'

        result = {
            'connection': fake_connection,
            'date': date_str,
            'count': connection_count,
            'total_updates': total_updates,
            'frequency_ratio': frequency_ratio,
            'is_suspicious': is_suspicious,
            'threshold_used': threshold_used,
            'threshold_percentage': threshold_used * 100,
            'data_coverage': data_source_info,  # Now using 7-day window when available
            'analysis_quality': 'adaptive',
            'note': f'Analyzed {total_updates:,} BGP announcements with adaptive threshold ({threshold_used*100:.2f}%)',
            'analysis_timestamp': datetime.now().isoformat()
        }

        return result

    except Exception as e:
        logger.error(f"Error analyzing connection frequency: {e}")
        return {
            'connection': fake_connection,
            'date': date_str,
            'error': str(e),
            'is_suspicious': True,  # Default to suspicious on error
            'data_coverage': 'error'
        }


def detect_forge_hijacks(updates_df, as_relationships,
                        target_as, fake_conn_cache_manager, full_day_data=None, prefix_to_as=None, *args, **kwargs):
    try:
        logger.info(f"Detecting forged path hijacks for AS{target_as}")

        if updates_df.empty:
            return [], updates_df

        analyzed_df = batch_check_connection_frequency(
            updates_df, as_relationships, target_as, fake_conn_cache_manager, full_day_data
        )

        suspicious_updates = analyzed_df[analyzed_df['connection_frequency_suspicious'] == True]

        alerts = []
        for idx, row in suspicious_updates.iterrows():
            try:
                # Read and deserialize fake_connections from DataFrame
                fake_connections_json = row.get('fake_connections', '[]')
                try:
                    fake_connections = json.loads(fake_connections_json) if fake_connections_json else []
                except (json.JSONDecodeError, TypeError):
                    fake_connections = []
                prefix = row.get('prefix', '')

                # Identify victim (legitimate prefix owner)
                victim_ases = []
                if prefix and prefix_to_as:
                    victim_ases = prefix_to_as.get(prefix, [])

                # Identify attacker: AS in fake connections; origin AS of the announcement
                attacker_ases = set()
                for fake_conn in fake_connections:
                    attacker_ases.add(fake_conn['as1'])
                    attacker_ases.add(fake_conn['as2'])
                attacker_list = list(attacker_ases)

                # Single value fields for reporting
                victim_as = victim_ases[0] if victim_ases else target_as
                origin_as = row.get('origin-as') or row.get('origin_as')
                # Merge all possible hijacker ASes
                all_hijacker_ases = set(attacker_list)
                if origin_as:
                    all_hijacker_ases.add(origin_as)
                hijacker_as_list = list(all_hijacker_ases)
                hijacker_as = hijacker_as_list[0] if hijacker_as_list else None
                # Fake connection string for evidence (e.g. "12345|67890")
                fake_connection_str = ''
                if fake_connections:
                    fc = fake_connections[0]
                    fake_connection_str = f"{fc.get('as1', '')}|{fc.get('as2', '')}"

                alert = {
                    'type': 'forged_path_hijack',
                    'target_as': target_as,
                    'timestamp': row['timestamp'],
                    'prefix': prefix,
                    'as_path': row.get('as-path', ''),
                    'confidence': 'medium',
                    'reason': 'Suspicious connection frequency detected',
                    'fake_connections': fake_connections,
                    'victim_ases': victim_ases,
                    'attacker_ases': attacker_list,
                    'victim_as': victim_as,
                    'hijacker_as': hijacker_as,
                    'hijacker_as_list': hijacker_as_list,
                    'expected_origin': victim_as,
                    'fake_connection': fake_connection_str,
                    'details': {
                        'date': row.get('date', ''),
                        'analysis_type': 'connection_frequency'
                    }
                }
                alerts.append(alert)

            except Exception as e:
                logger.warning(f"Error generating alert for suspicious update {idx}: {e}")
                continue

        logger.info(f"Detected {len(alerts)} potential forged path hijacks")
        return alerts, analyzed_df

    except Exception as e:
        logger.error(f"Error detecting forged path hijacks: {e}")
        return [], updates_df


def validate_hijack_detection(hijack_alerts, updates_df):
    try:
        validation = {
            'total_alerts': len(hijack_alerts),
            'alerts_by_type': {},
            'temporal_distribution': {},
            'validation_passed': True,
            'issues': []
        }

        for alert in hijack_alerts:
            alert_type = alert.get('type', 'unknown')
            validation['alerts_by_type'][alert_type] = validation['alerts_by_type'].get(alert_type, 0) + 1

        timestamps = [alert['timestamp'] for alert in hijack_alerts if 'timestamp' in alert]
        if len(timestamps) > 1:
            time_diffs = []
            sorted_times = sorted(timestamps)
            for i in range(1, len(sorted_times)):
                try:
                    dt1 = datetime.fromisoformat(sorted_times[i-1].replace('Z', '+00:00'))
                    dt2 = datetime.fromisoformat(sorted_times[i].replace('Z', '+00:00'))
                    time_diffs.append((dt2 - dt1).total_seconds())
                except:
                    continue

            if time_diffs and all(diff < 60 for diff in time_diffs):
                validation['issues'].append("All alerts clustered within 1 minute - possible false positive")

        valid_alerts = 0
        for alert in hijack_alerts:
            if 'timestamp' in alert and 'prefix' in alert:
                matching_updates = updates_df[
                    (updates_df['timestamp'] == alert['timestamp']) &
                    (updates_df['prefix'] == alert['prefix'])
                ]
                if not matching_updates.empty:
                    valid_alerts += 1

        if valid_alerts != len(hijack_alerts):
            validation['issues'].append(f"Only {valid_alerts}/{len(hijack_alerts)} alerts correspond to actual updates")
            validation['validation_passed'] = False

        return validation

    except Exception as e:
        logger.error(f"Error validating hijack detection: {e}")
        return {
            'validation_passed': False,
            'error': str(e)
        }
