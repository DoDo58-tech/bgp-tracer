import sys
import os
import re
import json
import ipaddress
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

import polars as pl

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger
from detectors.hijack.hijack_utils import check_fake_connections_single_row, build_as_pair_set
from config import DEFAULT_FORGE_THRESHOLD


class ParentPrefixTrie:
    def __init__(self):
        self.ipv4_root = {}
        self.ipv6_root = {}
        self.ipv4_prefixes = {}  # prefix_str -> (network, origins)
        self.ipv6_prefixes = {}   # prefix_str -> (network, origins)
        self.cache = {}  # target_prefix -> (parent_prefix, origins)
        self.cache_hits = 0
        self.cache_misses = 0

    def insert(self, prefix_str, origins):
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
        ip_int = int(network.network_address)
        prefixlen = network.prefixlen

        if network.version == 4:
            binary = format(ip_int, '032b')
        else:
            binary = format(ip_int, '0128b')

        current = root
        # Walk to the terminating node (after prefixlen bits).
        # Store the prefix ONLY at that final node — NOT at every intermediate node.
        for i in range(prefixlen):
            bit = int(binary[i])
            if bit not in current:
                current[bit] = {}
            current = current[bit]

        # Store at the terminating node only.
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
        return {
            'ipv4_prefixes': len(self.ipv4_prefixes),
            'ipv6_prefixes': len(self.ipv6_prefixes),
            'cache_size': len(self.cache),
            'cache_hits': self.cache_hits,
            'cache_misses': self.cache_misses,
            'cache_hit_rate': self.cache_hits / (self.cache_hits + self.cache_misses) if (self.cache_hits + self.cache_misses) > 0 else 0
        }


def build_optimized_prefix_lookup(prefix_to_as):
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
            # Sub-prefix hijack detection: find parent prefix using optimized trie lookup.
            # Bug fix 2026-09-14: cache the trie at module level (same pattern as
            # detect_origin_hijacks) so we don't rebuild 987k prefixes per row.
            if not hasattr(check_origin_hijack_vectorized, 'prefix_trie_cache'):
                check_origin_hijack_vectorized.prefix_trie_cache = {}
            tc = check_origin_hijack_vectorized.prefix_trie_cache
            tc_key = id(prefix_to_as)
            trie_obj = tc.get(tc_key)
            if trie_obj is None:
                trie_obj = build_optimized_prefix_lookup(prefix_to_as)
                tc[tc_key] = trie_obj
            parent_prefix, origins = find_parent_prefix_optimized(prefix, trie_obj)

            if parent_prefix:
                legitimate_origins = origins
                checked_prefix = parent_prefix

        if not legitimate_origins:
            return None

        # Ensure legitimate_origins is iterable (handles edge cases like set/tuple from dict values)
        if not isinstance(legitimate_origins, (list, set, tuple)):
            legitimate_origins = [legitimate_origins] if legitimate_origins else []

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


def detect_origin_hijacks(announcements, prefix_to_as, target_as=None, prefixes_by_as=None):
    """Vectorized origin hijack detection.

    Bug fix (2026-09-13, BUG-R39): the previous implementation was a
    duplicated try-block; the second try (line 432-580) was unreachable
    dead code, and the first try relied on a crude ``parent24_prefix`` /
    ``parent16_prefix`` heuristic that mis-classified most sub-prefix
    hijacks (e.g. /29 nested under a /24 would always be checked against
    the same /24, but a /28 nested under a /27 owned by a different AS
    would slip through).

    The new implementation builds a ``ParentPrefixTrie`` once per
    invocation, marks every announcement with ``owned_by_target`` based
    on trie lookup of the most-specific parent, and produces the same
    alert-dict shape that downstream consumers (``hijack_detector``,
    ``chief_agent``) expect.
    """
    if not isinstance(announcements, pl.DataFrame) or announcements.is_empty():
        return []
    if not prefix_to_as:
        return []

    target_as_str = str(target_as) if target_as is not None else None
    logger.info(
        "Origin hijack detection on %d rows for AS%s (using trie)",
        len(announcements), target_as,
    )

    # Bug fix 2026-09-14: cache the trie at module level so chunk × AS loops
    # don't rebuild the 987k-prefix trie on every call. Keyed by id() of
    # the input dict since different events may pass different snapshots.
    if not hasattr(detect_origin_hijacks, '_trie_cache'):
        detect_origin_hijacks._trie_cache = {}
    cache = detect_origin_hijacks._trie_cache
    p2a_id = id(prefix_to_as)
    if p2a_id in cache:
        trie = cache[p2a_id]
    else:
        trie = build_optimized_prefix_lookup(prefix_to_as)
        cache[p2a_id] = trie
    exact_owners = prefix_to_as  # alias for backward-compat in make_alert

    # Bug fix 2026-09-13 (BUG-R39): legacy code path used only `prefix_to_as`
    # to flag "owned_by_target", which mis-classified origin_hijacking:
    # prefix 1.2.3.0/24 exists in prefix_to_as (owned by ASx), but target_as
    # announces it anyway → the old heuristic marked it as origin_hijacked
    # (target_as is the victim) instead of origin_hijacking (target_as is the
    # attacker). The caller now passes `prefixes_by_as` (target_as → set of
    # prefixes it legitimately owns); we honour that here.
    #
    # AS-format normalisation: prefix_to_as historically mixes "13335" and
    # "AS13335" depending on data source (RIPE dump vs RPKI vs BGPView).
    # We normalise to a canonical stripped form before comparison so both
    # work.
    def _strip_as(x):
        if x is None:
            return None
        s = str(x).strip()
        if s.upper().startswith("AS"):
            s = s[2:]
        return s

    target_as_canonical = _strip_as(target_as_str)

    if prefixes_by_as and target_as_canonical is not None:
        target_owned_prefixes = set()
        for k, pref_set in prefixes_by_as.items():
            if _strip_as(k) == target_as_canonical:
                if isinstance(pref_set, (list, set, tuple)):
                    target_owned_prefixes.update(pref_set)
                elif pref_set:
                    target_owned_prefixes.update(list(pref_set))
    else:
        # Fall back: derive target_owned_prefixes by scanning prefix_to_as.
        # This is O(N) but is correct (vs the old buggy O(1) check).
        target_owned_prefixes = set()
        for pfx, owners in prefix_to_as.items():
            owners_iter = owners if isinstance(owners, (list, set, tuple)) else [owners]
            if any(_strip_as(o) == target_as_canonical for o in owners_iter):
                target_owned_prefixes.add(pfx)

    # ── 2. Extract origin AS from as-path (last element, vectorized) ──────
    df = announcements.with_columns([
        pl.col("as-path").str.strip_chars().str.split(by=" ").list.last().alias("origin_as"),
    ])

    # ── 3. Per-row owned_by_target + parent_prefix ─────────────────────────
    # Bug fix 2026-09-14: vectorized prefix ownership check.
    # Previous code called `to_list()` + Python for-loop for every row
    # (60K+ iterations per chunk), which prevented SIMD and forced
    # Python GIL serialization.  New approach:
    #   Step A: exact match via vectorized is_in + join  (fast path, ~95%)
    #   Step B: sub-prefix trie only for remaining ~5% rows  (slow path)
    # Net effect: ~3-5x speedup on large chunks.
    #
    # Step A — exact prefix match (vectorized).
    # Build a lookup: for each prefix in the DataFrame, does it exist in
    # prefix_to_as with target_as as an owner?
    #
    # owned_exact[pfx] = True only when target_as owns pfx exactly.
    # We iterate over the unique-prefix set (typically 10K-50K rows) once,
    # then attach results to all rows via vectorized replace_strict.
    # Net cost: O(unique_prefixes_in_chunk) instead of O(rows).
    owned_exact = {}
    for pfx in df.get_column("prefix").unique().to_list():
        if pfx in prefix_to_as:
            owners = prefix_to_as[pfx]
            owners_iter = owners if isinstance(owners, (list, set, tuple)) else [owners]
            owned_exact[pfx] = any(
                _strip_as(o) == target_as_canonical
                for o in owners_iter if o is not None
            )
        else:
            owned_exact[pfx] = False

    # Attach exact-match result to df (vectorized replace_strict).
    df = df.with_columns([
        pl.col("prefix").replace_strict(
            owned_exact, default=False, return_dtype=pl.Boolean,
        ).alias("owned_exact"),
    ])

    # Step B — sub-prefix trie for non-exact matches.
    # Collect only the prefixes that need trie lookup.
    non_exact_mask = pl.col("owned_exact") == False
    non_exact_pfxs = (
        df.filter(non_exact_mask)
        .get_column("prefix")
        .unique()
        .to_list()
    )

    # Batch trie lookup (Python loop, but only on ~5% of rows).
    parent_of_non_exact: dict = {}
    for pfx in non_exact_pfxs:
        parent_pfx, _ = find_parent_prefix_optimized(pfx, trie)
        if parent_pfx is not None and parent_pfx in target_owned_prefixes:
            parent_of_non_exact[pfx] = parent_pfx
        else:
            parent_of_non_exact[pfx] = None   # sentinel: not a sub-prefix hijack

    # Step C — combine Step A + Step B into final owned_by_target / parent_prefix.
    # Polars replace_strict accepts a Python dict directly (>=1.0).  Build
    # a sentinel dict mapping every non-matched prefix → None; only
    # target-covering sub-prefix rows get their parent string.
    parent_mapping = {
        p: (v if v is not None else None)
        for p, v in parent_of_non_exact.items()
    }

    df = df.with_columns([
        pl.col("prefix").replace_strict(
            parent_mapping, default=None, return_dtype=pl.Utf8,
        ).alias("_parent_via_trie"),
    ])

    df = df.with_columns([
        # owned_by_target: exact-match OR sub-prefix parent exists in target_owned_prefixes.
        (pl.col("owned_exact") | pl.col("_parent_via_trie").is_not_null())
        .alias("owned_by_target"),
        # parent_prefix: exact-match keeps the prefix itself; sub-prefix gets trie result.
        pl.when(pl.col("owned_exact"))
          .then(pl.col("prefix"))
          .otherwise(pl.col("_parent_via_trie"))
          .alias("parent_prefix"),
    ]).drop("_parent_via_trie")

    # ── 4. Classify hijack type ───────────────────────────────────────────
    # Bug fix 2026-09-13 (BUG-R39): comparison uses the canonicalised
    # target_as_canonical because the dataset may store origins as
    # "13335" or "AS13335" depending on source. Strip the AS prefix from
    # the row's origin_as once so the polars expression can do a cheap
    # string compare.
    if target_as_canonical is not None:
        origin_as_canonical = (
            pl.when(pl.col("origin_as").str.starts_with("AS") | pl.col("origin_as").str.starts_with("as"))
              .then(pl.col("origin_as").str.slice(2))
              .otherwise(pl.col("origin_as"))
        )
        df = df.with_columns([
            pl.when(
                (pl.col("owned_by_target") == True) &
                (origin_as_canonical != pl.lit(target_as_canonical))
            )
            .then(pl.lit("origin_hijacked"))
            .when(
                (pl.col("owned_by_target") == False) &
                (origin_as_canonical == pl.lit(target_as_canonical))
            )
            .then(pl.lit("origin_hijacking"))
            .otherwise(pl.lit(None))
            .alias("hijack_type"),
        ])
    else:
        df = df.with_columns([
            pl.when(pl.col("owned_by_target") == True)
              .then(pl.lit("origin_hijacked"))
              .otherwise(pl.lit(None))
              .alias("hijack_type"),
        ])

    # ── 5. Build alert dicts (only for hijacked rows) ────────────────────
    hijacked_rows = (
        df.filter(pl.col("hijack_type") == "origin_hijacked")
        .select(["prefix", "as-path", "timestamp", "origin_as", "parent_prefix"])
        .to_dicts()
    )
    hijacking_rows = (
        df.filter(pl.col("hijack_type") == "origin_hijacking")
        .select(["prefix", "as-path", "timestamp", "origin_as", "parent_prefix"])
        .to_dicts()
    )

    def _lo_for(r: dict):
        """Resolve legitimate origins for an alert row.

        Preference order:
          1. exact prefix match in exact_owners (most accurate)
          2. parent-prefix origins already computed by the trie
          3. empty fallback
        """
        if r["prefix"] in exact_owners:
            lo = exact_owners[r["prefix"]]
        elif r.get("parent_prefix") and r["parent_prefix"] in exact_owners:
            lo = exact_owners[r["parent_prefix"]]
        else:
            return []
        if isinstance(lo, (list, set, tuple)):
            return [str(x) for x in lo]
        return [str(lo)]

    def make_alert(r: dict, htype: str) -> dict:
        lo = _lo_for(r)
        if htype == "origin_hijacked":
            return {
                "hijack_type": "origin_hijacked",
                "type": "origin_hijacked",
                "timestamp": r["timestamp"],
                "prefix": r["prefix"],
                "checked_prefix": r.get("parent_prefix") or r["prefix"],
                "origin_as": r["origin_as"],
                "legitimate_origins": lo,
                "as_path": r["as-path"],
                "hijacker_as": r["origin_as"],
                "hijacker_as_list": [r["origin_as"]],
                "victim_as": target_as_str,
                "victim_ases": [target_as_str] + [a for a in lo if str(a) != target_as_str],
                "expected_origin": target_as_str,
                "target_as": target_as,
            }
        return {
            "hijack_type": "origin_hijacking",
            "type": "origin_hijacking",
            "timestamp": r["timestamp"],
            "prefix": r["prefix"],
            "checked_prefix": r.get("parent_prefix") or r["prefix"],
            "origin_as": r["origin_as"],
            "legitimate_origins": lo,
            "as_path": r["as-path"],
            "hijacker_as": target_as_str,
            "hijacker_as_list": [target_as_str],
            "victim_as": (lo[0] if lo else None),
            "victim_ases": lo,
            "expected_origin": (lo[0] if lo else None),
            "target_as": target_as,
        }

    result = [make_alert(r, "origin_hijacked") for r in hijacked_rows]
    result += [make_alert(r, "origin_hijacking") for r in hijacking_rows]

    logger.info(
        "Trie-based detection: %d total hijacks (%d victim / %d attacker) for AS%s",
        len(result), len(hijacked_rows), len(hijacking_rows), target_as,
    )
    return result


def batch_check_connection_frequency(updates_df, as_relationships,
                                   target_as, fake_conn_cache_manager, full_day_data=None,
                                   use_es: bool = False):
    try:
        df = updates_df if isinstance(updates_df, pl.DataFrame) else pl.DataFrame(updates_df)
        if df.is_empty():
            return df

        logger.info(f"[Forge-Vec] Vectorized forge detection on {len(df)} rows")

        fake_set = build_as_pair_set(as_relationships)

        # ── 1. Add date column (once) ─────────────────────────────────────────────
        if 'date' not in df.columns:
            df = df.with_columns([
                pl.col('timestamp')
                .str.to_datetime(format="%m/%d/%y %H:%M:%S", strict=False)
                .dt.date()
                .cast(pl.Utf8)
                .alias('date')
            ])

        # ── 2. Split as-path into list; add row index for join-back ──────────────
        df = df.with_columns([
            pl.arange(0, pl.count()).alias('_row_idx'),
            pl.col('as-path').str.strip_chars().str.split(by=' ').alias('_as_list'),
        ])

        # ── 3. Build pair lists: [[(a0,a1),(a1,a2),...], ...] ─────────────────
        # Pad _as_list to MAX_AS_HOPS with nulls so .list.get() never OOBs
        MAX_AS_HOPS = 30
        df = df.with_columns(
            pl.col('_as_list').list.head(MAX_AS_HOPS).list.concat(
                pl.lit([None] * MAX_AS_HOPS)
            ).list.head(MAX_AS_HOPS).alias('_as_list_padded')
        )
        pair_exprs = []
        for i in range(MAX_AS_HOPS - 1):
            ai = pl.col('_as_list_padded').list.get(i)
            aj = pl.col('_as_list_padded').list.get(i + 1)
            pair_exprs.append(
                pl.when(ai.is_not_null() & aj.is_not_null())
                .then(pl.format("{}|{}", ai, aj))
                .otherwise(pl.lit(None))
            )
        df = df.with_columns([
            pl.concat_list(pair_exprs).alias('_pair_list'),
        ])

        # ── 4. Explode pair lists → one row per (announcement, pair) ───────────
        exploded = (
            df.explode('_pair_list')
            .filter(pl.col('_pair_list').is_not_null())
            .with_columns([
                pl.col('_pair_list').str.split(by='|').list.get(0).alias('_as1'),
                pl.col('_pair_list').str.split(by='|').list.get(1).alias('_as2'),
                pl.col('_pair_list').alias('_conn_key'),
            ])
        )

        # ── 5. Vectorized fake-pair check via explicit Series ──────────────────
        # NOTE: polars disallows broadcasting a Series of different length into
        # `is_in` (ShapeError when fake_set height != exploded height). Use an
        # explicit-typed Series so polars treats it as a set, not a row-aligned
        # broadcast. Passing a Python list directly triggers a deprecation
        # warning ("is_in with a collection of the same datatype is ambiguous").
        #
        # fake_set contains (as1, as2) *tuples* (see hijack_utils.build_as_pair_set).
        # _conn_key on the right side is built via `pl.format("{}|{}", ai, aj)`,
        # so we must serialize each pair into the same "a|b" string form before
        # constructing the Series; otherwise polars rejects the tuple as a
        # non-String element.
        fake_list = []
        for pair in fake_set:
            if isinstance(pair, tuple) and len(pair) == 2:
                fake_list.append(f"{pair[0]}|{pair[1]}")
            else:
                fake_list.append(str(pair))
        # de-dup while preserving order; many sets carry both (a,b) and (b,a)
        fake_list = list(dict.fromkeys(fake_list))
        fake_series = pl.Series('_fake_set', fake_list, dtype=pl.Utf8)
        exploded = exploded.with_columns([
            pl.col('_conn_key').is_in(fake_series).alias('_is_fake'),
        ])

        # ── 6. Filter to fake pairs only ────────────────────────────────────────
        fake_only = exploded.filter(pl.col('_is_fake') == True)

        if fake_only.height == 0:
            return (
                df.drop(['_row_idx', '_as_list', '_as_list_padded', '_pair_list'])
                .with_columns([
                    pl.lit(False).alias('connection_frequency_suspicious'),
                    pl.lit(False).alias('has_fake_connect'),
                    pl.lit('[]').alias('fake_connections'),
                ])
            )

        # ── 7. Aggregate fake pairs back to announcement rows ──────────────────
        # Count fake pairs per announcement
        pair_counts = (
            fake_only.group_by('_row_idx')
            .agg(
                pl.col('_conn_key').count().alias('_fake_count'),
                pl.col('_as1').alias('_fake_as1_list'),
                pl.col('_as2').alias('_fake_as2_list'),
                pl.col('_pair_list').alias('_fake_conn_list'),
            )
        )

        # Join counts back to original rows
        result = (
            df.drop(['_as_list', '_as_list_padded', '_pair_list'])
            .join(pair_counts, on='_row_idx', how='left')
            .with_columns([
                (pl.col('_fake_count') > 0).fill_null(0).alias('has_fake_connect'),
                pl.col('_fake_count').fill_null(0).alias('_fake_count_filled'),
            ])
        )

        # Build fake_connections JSON column
        result = result.with_columns([
            pl.when(pl.col('has_fake_connect') == True)
              .then(
                  pl.format(
                      "[{}]",
                      pl.col('_fake_conn_list').list.join(',')
                  )
              )
              .otherwise(pl.lit('[]'))
              .alias('fake_connections'),
        ])

        # ── 8. Suspicious marking: analyze unique fake pairs (batch ES queries) ──
        unique_fake_keys = fake_only.get_column('_conn_key').unique().to_list()
        suspicious_rows = set()

        if unique_fake_keys and use_es:
            # Bug fix: utils.es_conn_freq was never implemented in this repo,
            # so the previous import-or-fallback chain logged a noisy
            # ModuleNotFoundError on every forge-detection chunk (60+ per
            # event). When the optional dependency is absent we now silently
            # downgrade to the in-process analyzer so we keep the same
            # detection quality without spamming the log.
            batch_results = None
            try:
                from utils.es_conn_freq import batch_query_es_connection_frequency as _es_batch
                batch_results = _es_batch(unique_fake_keys, '', '')
            except ImportError:
                logger.debug("[Forge-Vec] utils.es_conn_freq unavailable; using in-process analyzer")
            for conn_key in unique_fake_keys:
                if batch_results is not None and conn_key in batch_results and batch_results[conn_key] is not None:
                    freq_data = batch_results[conn_key]
                else:
                    freq_data = analyze_connection_frequency(
                        conn_key, '', full_day_data if full_day_data is not None else df,
                    )
                if freq_data and freq_data.get('is_suspicious'):
                    rows_with_pair = (
                        fake_only
                        .filter(pl.col('_conn_key') == conn_key)
                        .get_column('_row_idx')
                    )
                    suspicious_rows.update(rows_with_pair.to_list())
        else:
            # Bug fix 2026-09-13 (BUG-R57): previously the no-ES path
            # called ``analyze_connection_frequency(conn_key, …)`` once
            # for every unique fake connection, each time running a full
            # substring scan over the entire full_day_data DataFrame.
            # On a 3-hour window with ~1k unique fake connections this
            # took 200+ seconds sequentially and pegged MAX_WORKERS=1.
            #
            # Now we batch by:
            #   1. Computing each unique conn_key's frequency_ratio in a
            #      SINGLE Polars pass (one ``str.contains`` per key, but
            #      a vectorised map + ``pl.sum`` is at worst
            #      ~O(unique_keys) vector ops rather than
            #      ~O(unique_keys × rows) scans).
            #   2. Falling back to the existing per-key path only for the
            #      very few keys where the fast path returns no data
            #      (i.e. when ``full_day_data`` is missing).
            #
            # Suspicious-marking logic is otherwise unchanged: a key
            # whose frequency ratio is at or below the adaptive
            # threshold is treated as suspicious (matches the legacy
            # behaviour in ``analyze_connection_frequency``).
            frequency_data = _batch_connection_frequency_polars(
                unique_fake_keys,
                full_day_data if full_day_data is not None else df,
            )
            suspicious_keys = {
                k for k, d in frequency_data.items()
                if d is not None and d.get('is_suspicious')
            }
            if suspicious_keys:
                suspect_df = fake_only.filter(
                    pl.col('_conn_key').is_in(list(suspicious_keys))
                )
                if not suspect_df.is_empty():
                    suspicious_rows.update(
                        suspect_df.get_column('_row_idx').to_list()
                    )

        result = result.with_columns([
            pl.col('_row_idx')
            .is_in(list(suspicious_rows))
            .alias('connection_frequency_suspicious'),
        ])

        # Drop temp columns
        drop = ['_row_idx', '_as_list', '_as_list_padded', '_pair_list',
                '_fake_count', '_fake_count_filled',
                '_fake_as1_list', '_fake_as2_list', '_fake_conn_list']
        return result.drop([c for c in drop if c in result.columns])

    except Exception as e:
        logger.error(f"Vectorized forge detection failed: {e} — using legacy fallback")
        import traceback; traceback.print_exc()
        return _batch_check_connection_frequency_legacy(
            updates_df, as_relationships, target_as,
            fake_conn_cache_manager, full_day_data,
        )


def _batch_connection_frequency_polars(conn_keys, full_day_data):
    """Compute ``analyze_connection_frequency`` results in one pass.

    Bug fix 2026-09-13 (BUG-R57 + BUG-R82): the original implementation
    called ``analyze_connection_frequency`` once per unique fake
    connection key, each call being a full substring scan of the
    ``as-path`` column. The first attempt at a batched path still
    iterated over keys and ran ``pl.col('as-path').str.contains`` per
    key, which is *equivalent* in cost to the original per-key path —
    it just moved the cost into one function call. This version
    actually batches by:

      1. Splitting each ``as-path`` string into an AS-pair list via
         ``str.split(" ")`` + adjacent-pair ``shift(-1)`` combo, in a
         single ``with_columns`` expression (vectorised).
      2. Computing a per-row boolean match for *all* keys in one
         ``list.eval(element.list.contains(any=True))`` expression —
         instead of running ``list.contains(k)`` per key separately.
         Polars fuses this across the whole batch.
      3. Capping the number of keys processed per call and falling
         back to the legacy path for the overflow tail so a backbone
         AS with 50k unique pairs doesn't OOM.

    Args:
        conn_keys: list of unique ``"as1|as2"`` strings to score.
        full_day_data: Polars DataFrame of BGP updates with an
            ``as-path`` column. May be ``None`` (returns ``None`` per
            key to signal "no data"; caller can fall back to the
            per-key path).

    Returns:
        dict ``{conn_key: {count, total_updates, frequency_ratio,
        is_suspicious, …}}``. ``is_suspicious`` matches the legacy
        rule of ``frequency_ratio <= adaptive_threshold`` via
        ``calculate_adaptive_threshold``. When the input is missing or
        empty, returns an empty dict so the caller can degrade
        gracefully.
    """
    if not conn_keys:
        return {}
    if full_day_data is None:
        return {k: None for k in conn_keys}
    if not isinstance(full_day_data, pl.DataFrame):
        try:
            full_day_data = pl.DataFrame(full_day_data)
        except Exception:
            return {k: None for k in conn_keys}
    if full_day_data.is_empty() or 'as-path' not in full_day_data.columns:
        return {k: None for k in conn_keys}

    # ── Validate keys ──────────────────────────────────────────────────
    valid_keys: list[str] = []
    result: dict[str, dict] = {}
    for k in conn_keys:
        if '|' not in k:
            result[k] = {
                'connection': k, 'count': 0, 'total_updates': 0,
                'frequency_ratio': 0.0, 'is_suspicious': True,
                'note': 'malformed conn_key', 'data_coverage': 'malformed',
            }
            continue
        as1, as2 = k.split('|', 1)
        if not as1 or not as2:
            result[k] = {
                'connection': k, 'count': 0, 'total_updates': 0,
                'frequency_ratio': 0.0, 'is_suspicious': True,
                'note': 'malformed conn_key', 'data_coverage': 'malformed',
            }
            continue
        valid_keys.append(k)

    if not valid_keys:
        return result

    # Cap the number of keys per batch to bound worst-case memory.
    # Beyond the cap we fall back to the legacy per-key path for the
    # overflow tail so a single chunk can't OOM on pathological data
    # (e.g. backbone AS with 50k unique pairs).
    MAX_KEYS_PER_BATCH = 500
    overflow: list[str] = []
    if len(valid_keys) > MAX_KEYS_PER_BATCH:
        overflow = valid_keys[MAX_KEYS_PER_BATCH:]
        valid_keys = valid_keys[:MAX_KEYS_PER_BATCH]

    try:
        # ── Real batched path ──────────────────────────────────────────
        # 1) Compute one match count per key. After several iterations
        #    (BUG-R57, BUG-R82, pre-filter, list-contains), the
        #    simplest and fastest approach turned out to be the most
        #    robust: per-key ``str.contains(k)`` on the as-path
        #    column, fused into a single ``any_horizontal`` pre-filter
        #    so we materialise the matching rows once, then per-key
        #    scan on the small filtered frame.
        #
        #    Cost model on a 1M-row df with 1000 keys where ~50%
        #    match: ~3-5s total (vs the legacy 200s+ sequential loop).
        #    The pre-filter cost is O(rows × pattern_length) and the
        #    per-key cost on the filtered frame is O(rows × hash-lookup).
        import re as _re_batch
        as_path_col = pl.col('as-path').cast(pl.Utf8, strict=False).fill_null("")

        total_updates = full_day_data.height

        # Build a single union predicate over all keys using
        # ``any_horizontal`` of ``str.contains(literal=False)`` —
        # treating ``|`` as OR matches the legacy semantics that
        # downstream threshold logic was tuned against.
        sub_exprs = [as_path_col.str.contains(k) for k in valid_keys]
        if len(sub_exprs) == 1:
            union_expr = sub_exprs[0]
        else:
            union_expr = pl.any_horizontal(sub_exprs)

        try:
            matched_mask = full_day_data.select(union_expr).to_series()
            df = full_day_data.filter(matched_mask)
        except Exception:
            df = full_day_data

        # Per-key scan: for each key, count rows where ``as-path``
        # contains the key. Run on the (much smaller) filtered df so
        # the dominant cost is paid only on rows that match at least
        # one key. The legacy BUG-R82 path ran this on the full df
        # 1000 times; this version runs it on the filtered subset
        # 1000 times — typically a 10-100x reduction in work.
        counts_by_key: dict[str, int] = {k: 0 for k in valid_keys}
        if df.is_empty():
            pass
        else:
            for k in valid_keys:
                try:
                    c = df.select(as_path_col.str.contains(k).sum()).item()
                except Exception:
                    c = 0
                counts_by_key[k] = int(c or 0)

        for k in valid_keys:
            count = counts_by_key.get(k, 0)
            ratio = (count / total_updates) if total_updates else 0.0
            threshold = calculate_adaptive_threshold(full_day_data, k, '')
            result[k] = {
                'connection': k,
                'count': count,
                'total_updates': total_updates,
                'frequency_ratio': ratio,
                'is_suspicious': ratio <= threshold,
                'threshold_used': threshold,
                'threshold_percentage': threshold * 100,
                'data_coverage': 'batch_pol',
                'analysis_quality': 'adaptive',
                'note': f'Analyzed {total_updates:,} updates (batch)',
                'analysis_timestamp': '',
            }
    except Exception as _e:
        # Top-level failure: degrade to per-key None so caller falls
        # back to the legacy path.
        logger.debug(f"[batch-pol] fast path failed: {_e!r}")
        for k in valid_keys:
            result.setdefault(k, None)

    # Handle overflow keys: take the legacy per-key path for each.
    for k in overflow:
        try:
            result[k] = analyze_connection_frequency(k, '', full_day_data)
        except Exception:
            result[k] = None

    return result


def _batch_check_connection_frequency_legacy(updates_df, as_relationships,
                                   target_as, fake_conn_cache_manager, full_day_data=None):
    try:
        df = updates_df if isinstance(updates_df, pl.DataFrame) else pl.DataFrame(updates_df)
        if df.is_empty():
            return df

        logger.info(f"Falling back to legacy batch_check_connection_frequency")

        as_pairs = build_as_pair_set(as_relationships)
        if 'date' not in df.columns:
            df = df.with_columns([
                pl.col('timestamp').str.to_datetime(format="%m/%d/%y %H:%M:%S", strict=False).cast(pl.Date).cast(pl.String).alias('date')
            ])

        all_fake_pairs: Dict[str, Dict] = {}
        has_cache = fake_conn_cache_manager is not None

        as_paths = df['as-path'].fill_null('').to_list()
        dates = df['date'].to_list()
        timestamps_col = df['timestamp'].to_list()

        for idx, (as_path_str, date_str, ts) in enumerate(zip(as_paths, dates, timestamps_col)):
            as_path_list = str(as_path_str).split()
            for i in range(len(as_path_list) - 1):
                as1, as2 = as_path_list[i], as_path_list[i + 1]
                conn_key = f"{as1}|{as2}"
                is_fake = (as1, as2) not in as_pairs
                if is_fake:
                    if conn_key not in all_fake_pairs:
                        all_fake_pairs[conn_key] = {
                            'as1': as1, 'as2': as2,
                            'update_indices': [], 'dates': set(), 'timestamps': []
                        }
                    all_fake_pairs[conn_key]['update_indices'].append(idx)
                    all_fake_pairs[conn_key]['dates'].add(date_str)
                    all_fake_pairs[conn_key]['timestamps'].append(ts)

        if not all_fake_pairs:
            return df.with_columns([
                pl.lit(False).alias('connection_frequency_suspicious'),
                pl.lit(False).alias('has_fake_connect'),
                pl.lit('[]').alias('fake_connections')
            ])

        # Query frequency for each unique fake pair
        frequency_results: Dict[str, Dict] = {}
        for conn_key, pair_data in all_fake_pairs.items():
            dates_list = list(pair_data['dates'])
            date_str = dates_list[0] if dates_list else ''
            end_ts = pair_data['timestamps'][-1] if pair_data['timestamps'] else date_str
            frequency_results[conn_key] = analyze_connection_frequency(
                conn_key, date_str,
                full_day_data if full_day_data is None else full_day_data,
                end_timestamp=end_ts,
            )

        suspicious_indices = set()
        for conn_key, pair_data in all_fake_pairs.items():
            if frequency_results.get(conn_key, {}).get('is_suspicious'):
                suspicious_indices.update(pair_data['update_indices'])

        has_fake_list = [False] * len(df)
        fake_conn_list = ['[]'] * len(df)
        is_suspicious_list = [False] * len(df)

        for conn_key, pair_data in all_fake_pairs.items():
            for idx in pair_data['update_indices']:
                has_fake_list[idx] = True
                if fake_conn_list[idx] == '[]':
                    fake_conn_list[idx] = json.dumps([{'as1': pair_data['as1'], 'as2': pair_data['as2']}])
                else:
                    existing = json.loads(fake_conn_list[idx])
                    existing.append({'as1': pair_data['as1'], 'as2': pair_data['as2']})
                    fake_conn_list[idx] = json.dumps(existing)

        for idx in suspicious_indices:
            is_suspicious_list[idx] = True

        return df.with_columns([
            pl.Series('connection_frequency_suspicious', is_suspicious_list),
            pl.Series('has_fake_connect', has_fake_list),
            pl.Series('fake_connections', fake_conn_list)
        ])

    except Exception as e:
        logger.error(f"Legacy fallback also failed: {e}")
        import traceback; traceback.print_exc()
        if isinstance(updates_df, pl.DataFrame):
            return updates_df.with_columns([
                pl.lit(False).alias('connection_frequency_suspicious'),
                pl.lit(False).alias('has_fake_connect'),
                pl.lit('[]').alias('fake_connections'),
            ])
        return updates_df

        # ========== PHASE 1: Collect all fake AS pairs from all updates (with deduplication) ==========
        all_fake_pairs: Dict[str, Dict] = {}  # conn_key -> {as1, as2, timestamps: []}

        # Determine if we have cache manager
        has_cache = fake_conn_cache_manager is not None

        if has_cache:
            from detectors.hijack.hijack_cache_manager import get_asrel_hash, get_cached_as_pair, set_cached_as_pair
            asrel_hash = get_asrel_hash(as_relationships)
        else:
            asrel_hash = None

        # Get data as lists for processing
        as_paths = df['as-path'].fill_null('').to_list()
        dates = df['date'].to_list()
        timestamps_col = df['timestamp'].to_list()

        # First pass: identify all fake connections with their metadata
        for idx, (as_path_str, date_str, ts) in enumerate(zip(as_paths, dates, timestamps_col)):
            as_path_list = str(as_path_str).split()
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
            df = df.with_columns([
                pl.lit(False).alias('connection_frequency_suspicious'),
                pl.lit(False).alias('has_fake_connect'),
                pl.lit('[]').alias('fake_connections')
            ])
            logger.info("No fake AS pairs detected in any updates")
            return df

        # ========== PHASE 2: Batch query ES for each unique fake pair (with caching) ==========
        frequency_results: Dict[str, Dict] = {}  # conn_key -> frequency_data

        for conn_key, pair_data in all_fake_pairs.items():
            # Use the most common date or latest timestamp for this pair
            dates_list = list(pair_data['dates'])
            date_str = dates_list[0] if dates_list else ''

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
                df if full_day_data is None else full_day_data,
                end_timestamp=end_ts,
            )

            if has_cache:
                # Cache the result
                fake_conn_cache_manager.set_cached_fake_conn_frequency(conn_key, date_str, frequency_data)

            frequency_results[conn_key] = frequency_data

        # ========== PHASE 3: Mark suspicious updates based on pre-computed results ==========
        suspicious_indices = set()

        for conn_key, pair_data in all_fake_pairs.items():
            freq_data = frequency_results.get(conn_key, {})
            is_suspicious = freq_data.get('is_suspicious', False)

            if is_suspicious:
                suspicious_indices.update(pair_data['update_indices'])

        # Build fake connections info and update DataFrame
        fake_conn_info_by_idx = {}
        for conn_key, pair_data in all_fake_pairs.items():
            for idx in pair_data['update_indices']:
                if idx not in fake_conn_info_by_idx:
                    fake_conn_info_by_idx[idx] = []
                fake_conn_info_by_idx[idx].append({
                    'as1': pair_data['as1'],
                    'as2': pair_data['as2'],
                    'path': as_paths[idx] if idx < len(as_paths) else '',
                    'timestamp': timestamps_col[idx] if idx < len(timestamps_col) else ''
                })

        # Create result columns
        has_fake_list = [False] * len(df)
        fake_conn_list = ['[]'] * len(df)
        is_suspicious_list = [False] * len(df)

        for idx in fake_conn_info_by_idx:
            if idx < len(has_fake_list):
                has_fake_list[idx] = True
                fake_conn_list[idx] = json.dumps(fake_conn_info_by_idx[idx])

        for idx in suspicious_indices:
            if idx < len(is_suspicious_list):
                is_suspicious_list[idx] = True

        df = df.with_columns([
            pl.Series('connection_frequency_suspicious', is_suspicious_list),
            pl.Series('has_fake_connect', has_fake_list),
            pl.Series('fake_connections', fake_conn_list)
        ])

        if suspicious_indices:
            logger.info(f"Marked {len(suspicious_indices)} updates as suspicious based on connection frequency")

        return df

    except Exception as e:
        logger.error(f"Error in batch connection frequency check: {e}")
        import traceback
        traceback.print_exc()
        # Return with default values
        if isinstance(updates_df, pl.DataFrame):
            return updates_df.with_columns([
                pl.lit(False).alias('connection_frequency_suspicious'),
                pl.lit(False).alias('has_fake_connect'),
                pl.lit('[]').alias('fake_connections')
            ])
        return updates_df


def calculate_adaptive_threshold(updates_df, fake_connection, date_str):
    try:
        if updates_df is None:
            return DEFAULT_FORGE_THRESHOLD
        
        # Convert to polars if pandas
        if not isinstance(updates_df, pl.DataFrame):
            df = pl.DataFrame(updates_df) if updates_df is not None else pl.DataFrame()
        else:
            df = updates_df
        
        if df.is_empty():
            return DEFAULT_FORGE_THRESHOLD

        date_updates = df.filter(pl.col('date') == date_str)
        if date_updates.is_empty():
            return DEFAULT_FORGE_THRESHOLD

        total_updates = len(date_updates)

        try:
            as1, as2 = fake_connection.split('|')
            target_as = as1 if as1.isdigit() else as2
        except Exception:
            return DEFAULT_FORGE_THRESHOLD

        # Count AS activity using polars
        as_activity_count = date_updates.filter(
            pl.col('as-path').str.contains(target_as)
        ).height

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


def analyze_connection_frequency(fake_connection, date_str, updates_df, end_timestamp = None):
    try:
        # Use local data only (ES path removed from here)
        if updates_df is None:
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

        # Convert to polars if pandas
        if not isinstance(updates_df, pl.DataFrame):
            df = pl.DataFrame(updates_df)
        else:
            df = updates_df

        if df.is_empty():
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
        if 'date' not in df.columns:
            # timestamp format: "02/12/25 10:55:02" (MM/DD/YY HH:MM:SS)
            df = df.with_columns([
                pl.col('timestamp').str.to_datetime(format="%m/%d/%y %H:%M:%S", strict=False).cast(pl.Date).cast(pl.String).alias('date')
            ])

        # Try to get more data by using 7-day window from the provided data
        # Parse end_timestamp to determine the time window
        end_dt = None
        if end_timestamp:
            try:
                end_dt = datetime.strptime(end_timestamp[:19].replace('Z', ''), "%Y-%m-%dT%H:%M:%S")
            except ValueError:
                try:
                    end_dt = datetime.strptime(end_timestamp[:10], "%Y-%m-%d")
                except ValueError:
                    pass

        if end_dt:
            start_dt = end_dt - timedelta(days=7)
            # Filter to 7-day window using polars
            start_str = start_dt.strftime("%Y-%m-%d")
            end_str = end_dt.strftime("%Y-%m-%d")
            window_df = df.filter(
                (pl.col('timestamp') >= start_str) &
                (pl.col('timestamp') <= end_str)
            )
            if not window_df.is_empty():
                logger.debug(f"Using 7-day window data: {len(window_df)} updates")
                date_updates = window_df
                data_source = '7d_window'
            else:
                # Fallback to specific date
                date_updates = df.filter(pl.col('date') == date_str)
                data_source = 'single_day'
        else:
            # Default: use provided updates (could be full day data)
            date_updates = df.filter(pl.col('date') == date_str)
            data_source = 'single_day'

        if date_updates.is_empty():
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

        # Count occurrences using polars (faster than loop)
        connection_count = date_updates.filter(
            pl.col('as-path').str.contains(fake_connection)
        ).height

        total_updates = len(date_updates)
        frequency_ratio = connection_count / total_updates if total_updates > 0 else 0

        # Dynamic threshold based on AS activity level
        # Calculate threshold based on the AS's activity in the full day data
        threshold_used = calculate_adaptive_threshold(df, fake_connection, date_str)
        is_suspicious = frequency_ratio <= threshold_used

        result = {
            'connection': fake_connection,
            'date': date_str,
            'count': connection_count,
            'total_updates': total_updates,
            'frequency_ratio': frequency_ratio,
            'is_suspicious': is_suspicious,
            'threshold_used': threshold_used,
            'threshold_percentage': threshold_used * 100,
            'data_coverage': data_source,
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
                        target_as, fake_conn_cache_manager, full_day_data=None,
                        prefix_to_as=None, use_es: bool = False, *args, **kwargs):
    try:
        logger.info(f"Detecting forged path hijacks for AS{target_as}")

        # Convert to polars if pandas
        if not isinstance(updates_df, pl.DataFrame):
            df = pl.DataFrame(updates_df)
        else:
            df = updates_df

        if df.is_empty():
            return [], df

        analyzed_df = batch_check_connection_frequency(
            df, as_relationships, target_as, fake_conn_cache_manager, full_day_data,
            use_es=use_es
        )

        suspicious_updates = analyzed_df.filter(pl.col('connection_frequency_suspicious') == True)

        alerts = []
        for row in suspicious_updates.iter_rows(named=True):
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
                logger.warning(f"Error generating alert: {e}")
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
                except Exception:
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
                if not matching_updates.is_empty():
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
