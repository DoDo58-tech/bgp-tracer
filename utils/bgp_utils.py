import sys
from typing import List, Dict, Set, Tuple, Optional, Any
from ipaddress import ip_network
import pandas as pd
import json
import hashlib
import os
from pathlib import Path
from collections import defaultdict

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import DEFAULT_ANOMALY_THRESHOLD
from utils.logger import setup_logger

logger = setup_logger(__name__)

# Cache directory for AS pair sets
_CACHE_DIR = Path(__file__).resolve().parent.parent / "cache"
_CACHE_DIR.mkdir(exist_ok=True)

def remove_consecutive_duplicates(as_path):
    as_list = as_path.split()
    unique_as_list = [as_list[i] for i in range(len(as_list)) if i == 0 or as_list[i] != as_list[i-1]]
    return ' '.join(unique_as_list)

def is_subprefix(prefix, parent_prefix):
    try:
        net1 = ip_network(prefix)
        net2 = ip_network(parent_prefix)
        
        if type(net1) != type(net2):
            return False
            
        return net1.subnet_of(net2) and net1 != net2
    except ValueError as e:
        logger.error(f"Invalid IP prefix format: {prefix} or {parent_prefix}, error: {e}")
        return False
    except TypeError as e:
        logger.error(f"IP version mismatch: {prefix} ({type(net1)}) vs {parent_prefix} ({type(net2)})")
        return False
    except Exception as e:
        logger.error(f"Error checking subprefix relationship: {e}")
        return False

def find_parent_prefix(prefix, prefix_to_as):
    try:
        target_net = ip_network(prefix)
        for p, asn in prefix_to_as.items():
            try:
                current_net = ip_network(p)
                if type(target_net) == type(current_net):
                    if is_subprefix(prefix, p):
                        return p, asn
            except ValueError:
                continue
    except ValueError as e:
        logger.error(f"Invalid target prefix format: {prefix}, error: {e}")
    except Exception as e:
        logger.error(f"Error finding parent prefix: {e}")
    return "", ""


class _TrieNode:
    __slots__ = ("children", "terminal")

    def __init__(self) -> None:
        self.children: Dict[int, "_TrieNode"] = {}
        self.terminal: bool = False


class PrefixTrie:
    def __init__(self) -> None:
        self.v4_root = _TrieNode()
        self.v6_root = _TrieNode()

    @staticmethod
    def _iter_bits(packed: bytes, bit_len: int):
        for i in range(bit_len):
            byte_index = i // 8
            bit_index = 7 - (i % 8)
            yield (packed[byte_index] >> bit_index) & 1

    def insert(self, prefix: str) -> None:
        try:
            net = ip_network(prefix, strict=False)
        except Exception:
            return
        root = self.v4_root if net.version == 4 else self.v6_root
        node = root
        packed = net.network_address.packed
        for bit in self._iter_bits(packed, net.prefixlen):
            nxt = node.children.get(bit)
            if nxt is None:
                nxt = _TrieNode()
                node.children[bit] = nxt
            node = nxt
        node.terminal = True

    def has_ancestor(self, prefix: str) -> bool:
        """Return True if any ancestor (including exact) of given prefix is terminal in trie."""
        try:
            net = ip_network(prefix, strict=False)
        except Exception:
            return False
        root = self.v4_root if net.version == 4 else self.v6_root
        node = root
        packed = net.network_address.packed
        # Walk bits of observed prefix; if any node along path is terminal → related
        for bit in self._iter_bits(packed, net.prefixlen):
            if node.terminal:
                return True
            nxt = node.children.get(bit)
            if nxt is None:
                return False
            node = nxt
        return node.terminal
    
    def find_most_specific_ancestor(self, prefix: str, prefix_to_as: Dict[str, str]) -> Tuple[str, str]:
        try:
            net = ip_network(prefix, strict=False)
        except Exception:
            return None, None
        
        # Use ip_network.supernet to efficiently find parents
        best_parent = None
        best_prefix_len = -1
        
        # Try increasingly broader network masks until we find a match
        for mask_length in range(net.prefixlen - 1, 0, -1):
            try:
                parent_net = net.supernet(new_prefix=mask_length)
                parent_prefix = str(parent_net)
                
                if parent_prefix in prefix_to_as:
                    if mask_length > best_prefix_len:
                        best_prefix_len = mask_length
                        best_parent = (parent_prefix, prefix_to_as[parent_prefix])
                        # Found the most specific parent
                        return best_parent
            except ValueError:
                # Invalid prefix length
                continue
        
        return best_parent if best_parent else (None, None)

def find_common_path_endings(as_paths, threshold=DEFAULT_ANOMALY_THRESHOLD):
    if not as_paths or len(as_paths) < 2:
        return []
    
    total_paths = len(as_paths)
    min_count = max(2, int(total_paths * threshold)) 
    
    path_segments = [path.split() for path in as_paths]
    
    # Group paths by their complete suffixes, starting from longest possible
    suffix_to_paths = {}
    
    # Find all valid suffixes and group paths by them
    for path_idx, segments in enumerate(path_segments):
        path_len = len(segments)
        
        for suffix_len in range(2, path_len + 1):
            suffix = segments[-suffix_len:] 
            suffix_str = " ".join(suffix)
            
            if suffix_str not in suffix_to_paths:
                suffix_to_paths[suffix_str] = set()
            suffix_to_paths[suffix_str].add(path_idx)
    
    # Filter suffixes that meet the threshold
    valid_suffixes = {}
    for suffix_str, path_indices in suffix_to_paths.items():
        if len(path_indices) >= min_count:
            valid_suffixes[suffix_str] = path_indices
    
    # Find maximal suffixes (remove those that are subsets of longer ones)
    maximal_suffixes = {}
    
    # Sort by length (longest first) to prioritize longer suffixes
    sorted_suffixes = sorted(valid_suffixes.items(), key=lambda x: len(x[0].split()), reverse=True)
    
    for suffix_str, path_indices in sorted_suffixes:
        is_maximal = True
        
        # Check if this suffix is a subset of any existing maximal suffix
        for existing_suffix, existing_paths in maximal_suffixes.items():
            # If the current suffix's paths are a subset of an existing suffix's paths
            # and the existing suffix is longer, then current suffix is not maximal
            if (path_indices.issubset(existing_paths) and 
                len(existing_suffix.split()) > len(suffix_str.split())):
                is_maximal = False
                break
        
        if is_maximal:
            # Remove any existing suffixes that are subsets of the current one
            to_remove = []
            for existing_suffix, existing_paths in maximal_suffixes.items():
                if (existing_paths.issubset(path_indices) and 
                    len(suffix_str.split()) > len(existing_suffix.split())):
                    to_remove.append(existing_suffix)
            
            for suffix_to_remove in to_remove:
                del maximal_suffixes[suffix_to_remove]
            
            maximal_suffixes[suffix_str] = path_indices
    
    # Convert to result format
    common_endings = []
    for suffix_str, path_indices in maximal_suffixes.items():
        suffix_paths = [as_paths[i] for i in path_indices]
        
        common_ending = {
            'ending': suffix_str,
            'length': len(suffix_str.split()),
            'count': len(path_indices),
            'percentage': len(path_indices) / total_paths,
            'paths': suffix_paths
        }
        common_endings.append(common_ending)
    
    common_endings.sort(key=lambda x: (x['count'], x['length']), reverse=True)
    
    return common_endings

def find_common_path_ending(as_paths):    
    common_endings = find_common_path_endings(as_paths, threshold=0.5)
    if common_endings:
        return common_endings[0]['ending'], common_endings[0]['length']
    return "", 0

def is_prefix_legitimate(prefix: str, origin_as: str, prefix_to_as: Dict[str, str]) -> Tuple[bool, str, str]:
    if prefix in prefix_to_as and prefix_to_as[prefix] == origin_as:  
        return True, origin_as, prefix
    
    if prefix in prefix_to_as and prefix_to_as[prefix] != origin_as:
        return False, prefix_to_as[prefix], prefix
    
    parent_prefix, expected_origin = find_parent_prefix(prefix, prefix_to_as)
    if parent_prefix:
        if expected_origin == origin_as:
            return True, expected_origin, parent_prefix
        else:
            return False, expected_origin, parent_prefix
    
    return False, "", ""

def get_as_prefixes(target_as: str, prefix_to_as: Dict[str, str]) -> Set[str]:
    return {prefix for prefix, asn in prefix_to_as.items() if asn == target_as}

def find_prefix_conflicts(prefix: str, owned_prefixes: Set[str]) -> Tuple[bool, str]:
    try:
        net = ip_network(prefix)
        for owned in owned_prefixes:
            owned_net = ip_network(owned)
            if net.subnet_of(owned_net) or owned_net.subnet_of(net):
                return True, owned
    except Exception:
        pass
    return False, ""

def _get_as_relationships_hash(as_relationships, file_paths=None):
    """
    Generate a hash of AS relationships for cache key.
    
    Args:
        as_relationships: AS relationships dictionary
        file_paths: List of AS relationship file paths used (for cache key)
    
    Returns:
        Cache key string
    """
    # If file paths are provided, use them for cache key (more efficient and handles monthly updates)
    if file_paths:
        # Use file paths and modification times for cache key
        path_info = []
        for fp in sorted(file_paths):
            try:
                fp_obj = Path(fp)
                if fp_obj.exists():
                    # Include file path and modification time
                    mtime = fp_obj.stat().st_mtime
                    path_info.append(f"{fp}:{mtime}")
            except Exception:
                path_info.append(fp)
        if path_info:
            content = "|".join(path_info)
            return hashlib.md5(content.encode()).hexdigest()
    
    # Fallback: hash the content (slower but works if file paths not available)
    providers = as_relationships.get('providers', {})
    peers = as_relationships.get('peers', {})
    
    # Sort for deterministic hashing
    providers_str = json.dumps(providers, sort_keys=True)
    peers_str = json.dumps(peers, sort_keys=True)
    
    content = f"{providers_str}|{peers_str}"
    return hashlib.md5(content.encode()).hexdigest()

def _build_as_pair_set(as_relationships):
    """Build a set of valid AS pairs for fast lookup."""
    valid_pairs = set()
    providers = as_relationships.get('providers', {})
    peers = as_relationships.get('peers', {})
    
    # Add provider relationships (bidirectional)
    for as2, provider_list in providers.items():
        for as1 in provider_list:
            valid_pairs.add((as1, as2))
            valid_pairs.add((as2, as1))  # Reverse direction
    
    # Add peer relationships (symmetric)
    for as1, peer_list in peers.items():
        for as2 in peer_list:
            valid_pairs.add((as1, as2))
            valid_pairs.add((as2, as1))  # Symmetric
    
    return valid_pairs

def _load_as_pair_cache_from_disk(cache_key: str) -> Optional[set]:
    """Load AS pair cache from disk if exists."""
    cache_file = _CACHE_DIR / f"as_pair_cache_{cache_key}.json"
    
    if not cache_file.exists():
        return None
    
    try:
        with open(cache_file, 'r', encoding='utf-8') as f:
            pairs_list = json.load(f)
        # Convert list of lists back to set of tuples
        cache_set = {tuple(pair) for pair in pairs_list}
        logger.info(f"Loaded AS pair cache from disk: {len(cache_set):,} pairs")
        return cache_set
    except Exception as e:
        logger.warning(f"Failed to load AS pair cache from disk: {e}")
        return None

def _save_as_pair_cache_to_disk(cache_key: str, cache_set: set):
    """Save AS pair cache to disk."""
    cache_file = _CACHE_DIR / f"as_pair_cache_{cache_key}.json"
    
    try:
        # Convert set of tuples to list of lists for JSON serialization
        pairs_list = [list(pair) for pair in cache_set]
        
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump(pairs_list, f)
        
        cache_size_mb = cache_file.stat().st_size / 1024 / 1024
        logger.info(f"Saved AS pair cache to disk: {len(cache_set):,} pairs ({cache_size_mb:.2f} MB)")
    except Exception as e:
        logger.warning(f"Failed to save AS pair cache to disk: {e}")

def get_as_pair_cache(as_relationships, use_disk_cache: bool = False, asrel_file_paths: Optional[List[str]] = None):
    """
    Build AS pair cache for fast lookup.
    
    Performance analysis:
    - Building AS pair set: ~1-2 seconds (acceptable for single run)
    - Lookup performance: O(1) set lookup vs O(1) dict+list lookup
    - Real bottleneck: millions of lookups during validation, not the lookup method
    
    Disk caching value:
    - Saves ~1-2 seconds on subsequent runs (if same AS relationships)
    - But building only takes 1-2 seconds, so value is limited
    - The real optimization is using set for O(1) lookup (already done)
    
    Args:
        as_relationships: AS relationships dictionary
        use_disk_cache: Whether to use disk cache (default: False - not recommended)
        asrel_file_paths: List of AS relationship file paths used (for cache key if enabled)
    
    Returns:
        Set of valid AS pairs (tuples) for O(1) lookup
    """
    if not use_disk_cache:
        # Direct build - simple and fast enough (1-2 seconds)
        return _build_as_pair_set(as_relationships)
    
    # Disk cache (optional, limited value)
    # Generate cache key from file paths (if available) or content hash
    cache_key = _get_as_relationships_hash(as_relationships, file_paths=asrel_file_paths)
    
    # Try to load from disk first
    cache_set = _load_as_pair_cache_from_disk(cache_key)
    
    if cache_set is not None:
        return cache_set
    
    # Build cache in memory
    logger.info("Building AS pair cache in memory...")
    cache_set = _build_as_pair_set(as_relationships)
    
    # Save to disk for future use
    _save_as_pair_cache_to_disk(cache_key, cache_set)
    
    return cache_set

def validate_as_path_relationships(as_path, as_relationships, as_pair_cache=None):
    """Validate AS path relationships. Optimized version with caching."""
    if as_pair_cache is None:
        as_pair_cache = _build_as_pair_set(as_relationships)
    
    segments = as_path.strip().split()
    if len(segments) < 2:
        return True, []
    
    invalid_pairs = []
    
    for i in range(len(segments) - 1):
        as1 = segments[i]
        as2 = segments[i + 1]
        
        # Fast lookup using set
        if (as1, as2) not in as_pair_cache:
            invalid_pairs.append(f"{as1}-{as2}")
    
    return len(invalid_pairs) == 0, invalid_pairs

def check_as_path_validity(as_path, as_relationships):
    return validate_as_path_relationships(as_path, as_relationships)[0]

def check_fake_connections_in_df_ultra_fast(df, as_relationships, use_disk_cache: bool = False, asrel_file_paths: Optional[List[str]] = None):
    """
    Ultra-fast version using batch AS pair extraction and bulk checking.
    
    This version extracts all AS pairs from all paths first, then checks them
    in bulk against the cache. This improves cache locality and reduces overhead.
    
    Args:
        df: DataFrame with AS paths
        as_relationships: AS relationships dictionary
        use_disk_cache: Whether to use disk cache for AS pairs
        asrel_file_paths: List of AS relationship file paths used
    
    Returns:
        DataFrame with has_fake_connect and exact_fake_connect columns
    """
    logger.info(f"Checking fake connections in {len(df)} announcements using ULTRA-FAST batch method...")
    
    if 'timestamp' in df.columns:
        df['timestamp'] = df['timestamp'].astype(str)
    
    if df['as-path'].dtype != 'object':
        df['as-path'] = df['as-path'].astype(str)
    
    as_pair_cache = get_as_pair_cache(as_relationships, use_disk_cache=use_disk_cache, asrel_file_paths=asrel_file_paths)
    
    paths_series = df['as-path'].fillna('')
    
    # Batch extract all AS pairs
    all_as_pairs = []
    row_indices = []
    pair_indices_in_path = []
    
    for idx, path in enumerate(paths_series):
        if not path or path == '':
            continue
        
        segments = path.strip().split()
        path_len = len(segments)
        
        if path_len < 2:
            continue
        
        for i in range(path_len - 1):
            as1 = segments[i]
            as2 = segments[i + 1]
            all_as_pairs.append((as1, as2))
            row_indices.append(idx)
            pair_indices_in_path.append(i)
    
    # Bulk check all pairs at once (better cache locality)
    invalid_mask = [pair not in as_pair_cache for pair in all_as_pairs]
    
    # Group invalid pairs by row index
    invalid_pairs_by_row = defaultdict(list)
    for i, is_invalid in enumerate(invalid_mask):
        if is_invalid:
            row_idx = row_indices[i]
            as1, as2 = all_as_pairs[i]
            invalid_pairs_by_row[row_idx].append(f"{as1}-{as2}")
    
    # Build result lists
    has_fake_connect_list = [False] * len(df)
    exact_fake_connect_list = [''] * len(df)
    
    for row_idx, pairs in invalid_pairs_by_row.items():
        has_fake_connect_list[row_idx] = True
        exact_fake_connect_list[row_idx] = ';'.join(pairs)
    
    df['has_fake_connect'] = has_fake_connect_list
    df['exact_fake_connect'] = exact_fake_connect_list
    
    fake_count = sum(has_fake_connect_list)
    logger.info(f"Completed ULTRA-FAST fake connection check: {fake_count}/{len(df)} announcements have fake connections")
    
    return df


def check_fake_connections_in_df(df, as_relationships, use_disk_cache: bool = False, asrel_file_paths: Optional[List[str]] = None, early_exit: bool = False, use_ultra_fast: bool = False):
    """
    Highly optimized version: build AS pair cache once and process efficiently.
    
    Performance optimizations:
    1. Ultra-fast mode: Extract all AS pairs first, then bulk check (best for large datasets, collects ALL fake connections)
    2. Early exit: Stop checking once fake connection found (if early_exit=True, but NOT recommended - will miss some fake connections)
    3. Batch processing: Process all AS pairs in batches
    4. Reduced string operations: Minimize string concatenations
    5. Vectorized operations where possible
    
    Args:
        df: DataFrame with AS paths
        as_relationships: AS relationships dictionary
        use_disk_cache: Whether to use disk cache for AS pairs (default: False)
        asrel_file_paths: List of AS relationship file paths used (for cache key based on file paths)
        early_exit: If True, stop checking a path once a fake connection is found (NOT recommended - will only collect first fake connection)
        use_ultra_fast: If True, use ultra-fast batch method (recommended for millions of records, collects ALL fake connections)
    
    Note:
        By default (early_exit=False), ALL fake connections in each path are collected.
        Use early_exit=True only if you only need to know IF there's a fake connection, not which ones.
    """
    # Use ultra-fast method if requested (best for very large datasets)
    if use_ultra_fast:
        return check_fake_connections_in_df_ultra_fast(df, as_relationships, use_disk_cache, asrel_file_paths)
    
    logger.info(f"Checking fake connections in {len(df)} announcements using optimized method (early_exit={early_exit})...")
    
    # Ensure timestamp column is string type to avoid pandas auto-parsing issues
    if 'timestamp' in df.columns:
        df['timestamp'] = df['timestamp'].astype(str)
    
    # Ensure as-path is string type
    if df['as-path'].dtype != 'object':
        df['as-path'] = df['as-path'].astype(str)
    
    # Get AS pair cache (from disk if available, otherwise build and save)
    # Pass file paths for better cache key (handles monthly updates correctly)
    as_pair_cache = get_as_pair_cache(as_relationships, use_disk_cache=use_disk_cache, asrel_file_paths=asrel_file_paths)
    
    # Pre-compute path segments for all rows (batch operation)
    paths_series = df['as-path'].fillna('')
    
    has_fake_connect_list = []
    exact_fake_connect_list = []
    
    # Process paths in batches for better cache locality
    batch_size = 10000
    total_rows = len(paths_series)
    
    for batch_start in range(0, total_rows, batch_size):
        batch_end = min(batch_start + batch_size, total_rows)
        batch_paths = paths_series.iloc[batch_start:batch_end]
        
        for path in batch_paths:
            if not path or path == '':
                has_fake_connect_list.append(False)
                exact_fake_connect_list.append('')
                continue
            
            # Fast path splitting (avoid multiple str() calls)
            segments = path.strip().split()
            path_len = len(segments)
            
            if path_len < 2:
                has_fake_connect_list.append(False)
                exact_fake_connect_list.append('')
                continue
            
            # Optimized checking with early exit option
            invalid_pairs = []
            found_fake = False
            
            for i in range(path_len - 1):
                as1 = segments[i]
                as2 = segments[i + 1]
                
                # Fast lookup using set (O(1))
                if (as1, as2) not in as_pair_cache:
                    found_fake = True
                    if early_exit:
                        # Early exit: found fake connection, stop checking this path
                        invalid_pairs = [f"{as1}-{as2}"]
                        break
                    else:
                        # Collect all invalid pairs
                        invalid_pairs.append(f"{as1}-{as2}")
            
            # Append results
            has_fake_connect_list.append(found_fake)
            exact_fake_connect_list.append(';'.join(invalid_pairs) if found_fake else '')
    
    # Assign results directly (faster than apply)
    df['has_fake_connect'] = has_fake_connect_list
    df['exact_fake_connect'] = exact_fake_connect_list
    
    fake_count = sum(has_fake_connect_list)
    logger.info(f"Completed fake connection check: {fake_count}/{len(df)} announcements have fake connections")
    
    return df

def detect_man_in_the_middle_hijack(
    as_path, 
    expected_path, 
    as_relationships,
    target_as
):
    if not as_path or not expected_path:
        return None
    
    current_path = as_path.strip().split()
    expected_path_list = expected_path.strip().split()
    
    target_in_expected = target_as in expected_path_list
    target_in_current = target_as in current_path

    suspicious_insertions = []
    attack_scenario = None
    
    # ========================================================================
    # SCENARIO 1: Target AS being hijacked (Victim Scenario)
    # Expected path contains target_as, but current path doesn't
    # ========================================================================
    if target_in_expected and not target_in_current:
        attack_scenario = 'victim'  # Target AS is a victim
        
        # Find all ASes that bypassed the target
        for i, asn in enumerate(current_path):
            if asn not in expected_path_list:
                # This AS shouldn't be in the path
                suspicious_insertions.append({
                    'asn': asn,
                    'position': i,
                    'reason': 'target_bypassed',
                    'severity': 'high'
                })
        
        # Check if path is significantly shorter (indicates bypass)
        if len(current_path) < len(expected_path_list):
            # Missing target AS and other ASes - high risk
            # Path length analysis
            path_length_anomaly = _detect_path_length_anomaly(current_path, expected_path_list)
        else:
            path_length_anomaly = {'detected': False, 'current_length': len(current_path), 
                                    'expected_length': len(expected_path_list), 
                                    'length_difference': len(current_path) - len(expected_path_list), 'anomaly_score': 0.0}
        
        # Routing pattern analysis (doesn't apply for bypass scenario)
        routing_pattern_anomaly = {'detected': True, 'anomalies': [
            {'type': 'target_as_bypassed', 'severity': 'high', 
             'details': f'Expected AS{target_as} in path but not present'}
        ], 'anomaly_count': 1, 'anomaly_score': 0.8}
        
        # Calculate risk score
        risk_score = _calculate_mitm_risk_score(
            len(suspicious_insertions),
            path_length_anomaly,
            routing_pattern_anomaly
        )
        
        # Lower threshold for victim scenario (0.2) since this is more critical
        if risk_score > 0.2:
            return {
                'attack_type': 'man_in_the_middle',
                'attack_scenario': 'victim',  # Target AS is being attacked
                'target_as': target_as,
                'observed_path': as_path,
                'expected_path': expected_path,
                'suspicious_insertions': suspicious_insertions,
                'path_length_anomaly': path_length_anomaly,
                'routing_pattern_anomaly': routing_pattern_anomaly,
                'risk_score': risk_score,
                'confidence': 'high' if risk_score > 0.7 else 'medium' if risk_score > 0.5 else 'low'
            }
    
    # ========================================================================
    # SCENARIO 2: Target AS appears in path - check for suspicious insertions
    # (Could be monitoring traffic or actively hijacking)
    # ========================================================================
    elif target_in_current:
        attack_scenario = 'attacker'  # Might be attacking others
        
        # Find the position of target AS in current path
        target_position = current_path.index(target_as)
        
        # Check for suspicious AS insertions BEFORE the target
        for i in range(target_position):
            asn = current_path[i]
            if asn not in expected_path_list:
                # Check if this AS has legitimate business relationship
                if not _is_legitimate_transit_as(asn, current_path, as_relationships, target_as):
                    suspicious_insertions.append({
                        'asn': asn,
                        'position': i,
                        'reason': 'unexpected_insertion_before_target'
                    })
        
        # Check for suspicious AS insertions AFTER the target
        for i in range(target_position + 1, len(current_path)):
            asn = current_path[i]
            if asn not in expected_path_list:
                if not _is_legitimate_transit_as(asn, current_path, as_relationships, target_as):
                    suspicious_insertions.append({
                        'asn': asn,
                        'position': i,
                        'reason': 'unexpected_insertion_after_target'
                    })
        
        # Check for path length anomalies
        path_length_anomaly = _detect_path_length_anomaly(current_path, expected_path_list)
        
        # Check for suspicious routing patterns
        routing_pattern_anomaly = _detect_mtim_routing_pattern_anomaly(current_path, target_as, as_relationships)
        
        # Calculate risk score
        risk_score = _calculate_mitm_risk_score(
            len(suspicious_insertions),
            path_length_anomaly,
            routing_pattern_anomaly
        )
        
        # Original threshold for attacker scenario
        if risk_score > 0.3:
            return {
                'attack_type': 'man_in_the_middle',
                'attack_scenario': 'attacker',  # Target AS might be attacking
                'target_as': target_as,
                'observed_path': as_path,
                'expected_path': expected_path,
                'suspicious_insertions': suspicious_insertions,
                'path_length_anomaly': path_length_anomaly,
                'routing_pattern_anomaly': routing_pattern_anomaly,
                'risk_score': risk_score,
                'confidence': 'high' if risk_score > 0.7 else 'medium' if risk_score > 0.5 else 'low'
            }
    
    # ========================================================================
    # SCENARIO 3: Target AS not in either path - not relevant
    # ========================================================================
    else:
        # Target AS doesn't appear in either path - this path is not relevant
        pass
    
    return None

def _is_legitimate_transit_as(
    asn, 
    path, 
    as_relationships, 
    target_as
):
    providers = as_relationships.get('providers', {})
    peers = as_relationships.get('peers', {})
    
    # Check if AS has provider-customer relationship with any AS in the path
    for other_as in path:
        if other_as != asn:
            # Check provider-customer relationships
            if (asn in providers.get(other_as, []) or 
                other_as in providers.get(asn, [])):
                return True
            
            # Check peer relationships
            if asn in peers.get(other_as, []) or other_as in peers.get(asn, []):
                return True
    
    # Check if AS is a known transit provider for the target AS
    if target_as in providers.get(asn, []):
        return True
    
    return False

def _detect_path_length_anomaly(current_path, expected_path):
    current_length = len(current_path)
    expected_length = len(expected_path)
    
    length_diff = current_length - expected_length
    
    # Calculate anomaly score based on length difference
    if length_diff <= 0:
        anomaly_score = 0.0
    elif length_diff == 1:
        anomaly_score = 0.3
    elif length_diff == 2:
        anomaly_score = 0.6
    else:
        anomaly_score = 0.9
    
    return {
        'detected': length_diff > 0,
        'current_length': current_length,
        'expected_length': expected_length,
        'length_difference': length_diff,
        'anomaly_score': anomaly_score
    }

def _detect_mtim_routing_pattern_anomaly(
    path, 
    target_as, 
    as_relationships
) -> Dict[str, Any]:
    anomalies = []
    
    # Check for sudden changes in routing patterns
    for i in range(len(path) - 1):
        as1 = path[i]
        as2 = path[i + 1]
        
        # Check if this AS pair has valid business relationship
        is_valid, invalid_pairs = validate_as_path_relationships(f"{as1} {as2}", as_relationships)
        
        if not is_valid:
            anomalies.append({
                'type': 'invalid_relationship',
                'as_pair': f"{as1}-{as2}",
                'position': i,
                'severity': 'high'
            })
    
    # Check for suspicious AS sequences (e.g., AS1 -> AS2 -> AS1)
    for i in range(len(path) - 2):
        if path[i] == path[i + 2] and path[i] != path[i + 1]:
            anomalies.append({
                'type': 'circular_routing',
                'as_sequence': f"{path[i]} -> {path[i+1]} -> {path[i+2]}",
                'position': i,
                'severity': 'medium'
            })
    
    # Check if target AS appears multiple times in path (potential hijacking)
    target_count = path.count(target_as)
    if target_count > 1:
        anomalies.append({
            'type': 'target_as_duplication',
            'count': target_count,
            'severity': 'high'
        })
    
    return {
        'detected': len(anomalies) > 0,
        'anomalies': anomalies,
        'anomaly_count': len(anomalies),
        'anomaly_score': min(1.0, len(anomalies) * 0.3)
    }

def _calculate_mitm_risk_score(
    suspicious_insertions,
    path_length_anomaly: Dict[str, Any],
    routing_pattern_anomaly: Dict[str, Any]
):
    base_score = 0.0
    
    # Suspicious insertions weight: 40%
    if suspicious_insertions > 0:
        base_score += 0.4 * min(1.0, suspicious_insertions * 0.5)
    
    # Path length anomaly weight: 30%
    if path_length_anomaly.get('detected', False):
        base_score += 0.3 * path_length_anomaly.get('anomaly_score', 0.0)
    
    # Routing pattern anomaly weight: 30%
    if routing_pattern_anomaly.get('detected', False):
        base_score += 0.3 * routing_pattern_anomaly.get('anomaly_score', 0.0)
    
    return min(1.0, base_score)

def analyze_mitm_patterns(
    announcements_df,
    target_as,
    as_relationships
):
    mitm_attacks = []
    
    # Group announcements by prefix to analyze routing patterns
    for prefix, prefix_group in announcements_df.groupby('prefix'):
        paths = prefix_group['as-path'].tolist()
        
        if len(paths) < 2:
            continue  # Need multiple paths to detect anomalies
        
        # Find the most common (likely legitimate) path
        path_counts = {}
        for path in paths:
            path_counts[path] = path_counts.get(path, 0) + 1
        
        # Sort by frequency
        sorted_paths = sorted(path_counts.items(), key=lambda x: x[1], reverse=True)
        legitimate_path = sorted_paths[0][0]
        
        # Check each path for MITM attacks
        for path, count in sorted_paths[1:]:
            if count < 2:  # Skip paths with very few occurrences
                continue
                
            # Detect MITM in this path
            mitm_result = detect_man_in_the_middle_hijack(
                path, legitimate_path, as_relationships, target_as
            )
            
            if mitm_result:
                mitm_result.update({
                    'prefix': prefix,
                    'legitimate_path': legitimate_path,
                    'suspicious_path': path,
                    'announcement_count': count,
                    'legitimate_count': sorted_paths[0][1]
                })
                mitm_attacks.append(mitm_result)
    
    return mitm_attacks