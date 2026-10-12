import os
import sys
import gc
import pandas as pd
import polars as pl
from typing import List
from pathlib import Path
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger
from config import PROJECT_ROOT, PATHPROB_SEARCH_PATHS, PATHPROB_AE_ROOT, DEFAULT_LEAK_THRESHOLD, MAX_WORKERS, IO_BUSY_THRESHOLD
from detectors.unified_result import wrap, DetectionType
from detectors.input_validation import InputValidationError, validate_detection_request

def _parse_time_window(value):
    if hasattr(value, "year") and hasattr(value, "month") and hasattr(value, "day"):
        return value

    value_str = str(value).strip()
    if not value_str:
        raise ValueError("empty time value")

    candidates = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
    ]
    for fmt in candidates:
        try:
            return datetime.strptime(value_str, fmt)
        except ValueError:
            continue

    iso_value = value_str.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(iso_value)
    except ValueError as exc:
        raise ValueError(f"Unsupported time format: {value_str}") from exc

def find_pathprob_file(pathprob_file = None):
    """
    Find pathprob.txt file in common locations.
    
    Args:
        pathprob_file: Optional explicit path to pathprob.txt
        
    Returns:
        Path to pathprob.txt if found, None otherwise
    """
    if pathprob_file and os.path.exists(pathprob_file):
        logger.info(f"Using specified PathProb file: {pathprob_file}")
        return pathprob_file
    
    # Try all search paths
    for search_path in PATHPROB_SEARCH_PATHS:
        if isinstance(search_path, str):
            search_path = Path(search_path)
        
        if search_path.exists() and search_path.is_file():
            logger.info(f"Found PathProb file at: {search_path}")
            return str(search_path)
        elif search_path.exists() and search_path.is_dir():
            # If it's a directory, try pathprob.txt inside it
            candidate = search_path / "pathprob.txt"
            if candidate.exists():
                logger.info(f"Found PathProb file at: {candidate}")
                return str(candidate)
    
    # If not found, provide helpful error message
    logger.error("PathProb file not found in any of the following locations:")
    for i, search_path in enumerate(PATHPROB_SEARCH_PATHS, 1):
        logger.error(f"  {i}. {search_path}")
    logger.error(f"\nTo fix this issue:")
    logger.error(f"  1. Generate pathprob.txt using PathProb_AE:")
    logger.error(f"     cd {PATHPROB_AE_ROOT}")
    logger.error(f"     python3 infer_prob/asrel_prob.py --path_dir <path_dir> --print_dir <print_dir>")
    logger.error(f"  2. Or set PATHPROB_FILE environment variable:")
    logger.error(f"     export PATHPROB_FILE=/path/to/pathprob.txt")
    logger.error(f"  3. Or place pathprob.txt in: {PROJECT_ROOT / 'data' / 'pathprob' / 'pathprob.txt'}")
    
    return None


def _read_prob(probfile):
    prob = {}
    try:
        with open(probfile, 'r', encoding='utf-8') as f:
            for line in f:
                if line and not line.startswith("#"):
                    parts = line.strip().split("|")
                    if len(parts) >= 5:
                        as1, as2 = int(parts[0]), int(parts[1])
                        p2c, p2p, c2p = float(parts[2]), float(parts[3]), float(parts[4])
                        probs = [p2c, p2p, c2p]
                        if as1 > as2:
                            probs = [c2p, p2p, p2c]
                        prob[(min(as1, as2), max(as1, as2))] = probs
    except Exception as e:
        logger.error(f"Error reading PathProb file {probfile}: {e}")
    
    logger.info(f"Loaded {len(prob)} AS relationship probabilities from {probfile}")
    return prob


def _parse_as_path(as_path_str):
    if not as_path_str:
        return []
    if '|' in as_path_str:
        path = as_path_str.split('|')
    else:
        path = as_path_str.split()
    
    path = [asn.strip() for asn in path if asn.strip()]
    return path


def _detect_leak_by_prob(path, asrelprob, threshold = DEFAULT_LEAK_THRESHOLD):
    if len(path) < 2:
        return False, 1.0

    prob = 1.0
    c2p0 = 1.0

    for i in range(len(path) - 1):
        as1, as2 = int(path[i]), int(path[i + 1])
        link = (min(as1, as2), max(as1, as2))

        if link in asrelprob:
            p2c, _, c2p = asrelprob[link]
        elif link[::-1] in asrelprob:
            c2p, _, p2c = asrelprob[link[::-1]]
        else:
            continue

        prob = min(p2c + c2p0 - p2c * c2p0, prob)
        c2p0 = c2p

    is_leak = prob < threshold
    return is_leak, prob


def detect_route_leaks_in_announcements_slow(
    announcements_df,
    asrelprob,
    threshold
):
    """
    leak（）
    """
    leaks = []

    # Convert polars to pandas if needed (handles both polars and pandas)
    if not isinstance(announcements_df, pd.DataFrame):
        # Check if it's a polars DataFrame
        try:
            if hasattr(announcements_df, 'to_pandas'):
                announcements_df = announcements_df.to_pandas()
            elif hasattr(announcements_df, 'iter_rows'):
                # It's a polars DataFrame, convert manually
                records = list(announcements_df.iter_rows(named=True))
                announcements_df = pd.DataFrame(records)
            else:
                # Fallback: try to convert from dict/list
                announcements_df = pd.DataFrame(announcements_df)
        except Exception as e:
            logger.warning(f"Failed to convert DataFrame to pandas: {e}")
            return leaks

    if announcements_df is None or announcements_df.empty:
        return leaks

    if 'as-path' not in announcements_df.columns:
        logger.warning("DataFrame missing 'as-path' column")
        return leaks

    for idx, row in announcements_df.iterrows():
        as_path_str = str(row.get('as-path', ''))
        if not as_path_str:
            continue

        path = _parse_as_path(as_path_str)
        if len(path) < 2:
            continue

        is_leak, leak_prob = _detect_leak_by_prob(path, asrelprob, threshold)

        if is_leak:
            leak_event = {
                "timestamp": row.get('timestamp', row.get('time', '')),
                "prefix": row.get('prefix', ''),
                "as-path": as_path_str,
                "origin-as": path[-1] if path else '',
                "leak_probability": leak_prob,
                "threshold": threshold,
                "path_length": len(path),
                "detection_method": "PathProb"
            }

            for field in ['collector', 'peer-as', 'type']:
                if field in row:
                    leak_event[field] = row[field]

            leaks.append(leak_event)

    return leaks


def detect_route_leaks_vectorized(
    announcements_df,
    asrelprob,
    threshold,
    max_leaks: int = 0
):
    """
    leak - polars

    Args:
        announcements_df: DataFrame (polars)
        asrelprob: AS
        threshold: leak
        max_leaks: leak，0

    Returns:
        leak
    """
    leaks = []
    leak_count = 0
    try:
        threshold = float(threshold)
    except (TypeError, ValueError):
        logger.warning("Invalid route leak threshold %r; skipping leak detection", threshold)
        return leaks

    # Convert to polars if pandas
    if not isinstance(announcements_df, pl.DataFrame):
        df = pl.DataFrame(announcements_df)
    else:
        df = announcements_df
    
    if df.is_empty():
        return leaks
    
    if 'as-path' not in df.columns:
        logger.warning("DataFrame missing 'as-path' column")
        return leaks
    
    try:
        # 1. AS（）
        # ：polars 0.19+  list.eval API ，
        try:
            # 
            # polars  str.strip_chars()  str.strip()
            df = df.with_columns([
                pl.col('as-path').str.split(by=" ").list.eval(pl.element().str.strip_chars()).alias('_path_list')
            ])
        except AttributeError:
            # ：，strip_chars
            df = df.with_columns([
                pl.col('as-path').str.split(by=" ").alias('_path_list')
            ])
            # strip_chars（polars）
            try:
                df = df.with_columns([
                    pl.col('_path_list').list.eval(pl.element().str.strip_chars()).alias('_path_list')
                ])
            except AttributeError:
                # ：
                logger.warning("Polars version too old for string operations, skipping path cleanup")
                pass
        
        # 2. 
        df = df.with_columns([
            pl.col('_path_list').list.len().alias('_path_len')
        ])
        df = df.filter(pl.col('_path_len') >= 2)
        
        if df.is_empty():
            return leaks
        
        # 3. link（）
        link_cache = {}
        for link, probs in asrelprob.items():
            link_cache[link] = probs
            link_cache[link[::-1]] = [probs[2], probs[1], probs[0]]

        # ── Optimization 2026-09-17: replace per-row map_elements with
        df = df.with_row_index(name="_path_id")
        # 1. Edge-explode: one row per (path_id, edge_idx) pair.
        edges = (
            df.select(["_path_id", "_path_list"])
            .with_columns(
                pl.col("_path_list").list.slice(0, pl.col("_path_list").list.len() - 1).alias("_from_list"),
                pl.col("_path_list").list.slice(1).alias("_to_list"),
            )
            .with_columns(
                pl.int_range(pl.len()).alias("_edge_idx"),
            )
            .select([
                pl.col("_path_id").repeat_by(pl.col("_from_list").list.len()).explode().alias("_path_id"),
                pl.col("_from_list").explode().alias("_from"),
                pl.col("_to_list").explode().alias("_to"),
            ])
            .with_columns([
                pl.col("_from").cast(pl.Int64, strict=False).alias("_from_i"),
                pl.col("_to").cast(pl.Int64, strict=False).alias("_to_i"),
            ])
            .with_columns([
                pl.min_horizontal("_from_i", "_to_i").alias("_a"),
                pl.max_horizontal("_from_i", "_to_i").alias("_b"),
            ])
            .filter(pl.col("_from_i").is_not_null() & pl.col("_to_i").is_not_null())
        )
        # 2. Convert link_cache to a Polars DataFrame for the join.
        try:
            link_records = []
            for k, v in link_cache.items():
                if not isinstance(k, tuple) or len(k) != 2:
                    continue
                try:
                    a, b = int(k[0]), int(k[1])
                except (TypeError, ValueError):
                    continue
                p2c, _, c2p = v[0], v[1], v[2]
                link_records.append((a, b, float(p2c), float(c2p)))
            link_df = pl.DataFrame(
                link_records,
                schema=["_a", "_b", "_p2c", "_c2p"],
                orient="row",
            )
        except Exception as exc:
            logger.error(f"[leak_detector] failed to build link DataFrame: {exc}")
            return leaks
        # 3. Hash-join to fetch per-edge (p2c, c2p) tuples.
        joined = edges.join(link_df, on=["_a", "_b"], how="left")
        # 4. Compute leak probability per path:
        joined = joined.with_columns([
            (pl.col("_p2c") + pl.col("_c2p").shift(1).fill_null(1.0) -
             pl.col("_p2c") * pl.col("_c2p").shift(1).fill_null(1.0))
            .cum_min()
            .over("_path_id")
            .alias("_prob_running"),
        ])
        # Final probability per path = last value of the running min.
        path_probs = (
            joined.group_by("_path_id")
            .agg(pl.col("_prob_running").last().alias("_leak_prob"))
        )
        df = df.join(path_probs, on="_path_id", how="left").with_columns(
            pl.col("_leak_prob").fill_null(1.0)
        )

        # 5. leak（null，Polars）
        leak_df = df.filter(
            pl.col('_leak_prob').is_not_null() & (pl.col('_leak_prob') < threshold)
        )

        if leak_df.is_empty():
            return leaks

        # 6. 
        for row in leak_df.iter_rows(named=True):
            # max_leaks，
            if max_leaks > 0 and leak_count >= max_leaks:
                logger.warning(f"Reached max_leaks limit ({max_leaks}), truncating results")
                break
            
            path = row.get('_path_list', [])

            leak_event = {
                "timestamp": row.get('timestamp', row.get('time', '')),
                "prefix": row.get('prefix', ''),
                "as-path": row.get('as-path', ''),
                "origin-as": path[-1] if path else '',
                "leak_probability": row.get('_leak_prob', 1.0),
                "threshold": threshold,
                "path_length": len(path),
                "detection_method": "PathProb"
            }

            # 
            for field in ['collector', 'peer-as', 'peer_as', 'type']:
                if field in row and row[field] is not None:
                    leak_event[field] = row[field]

            leaks.append(leak_event)
            leak_count += 1
        
        logger.debug(f"Vectorized leak detection: {len(leaks)} leaks from {len(leak_df)} candidates")
        
    except Exception as e:
        logger.error(f"Error in vectorized leak detection: {e}")
        # 
        logger.info("Falling back to row-by-row detection")
        return detect_route_leaks_in_announcements_slow(announcements_df, asrelprob, threshold)
    
    return leaks


def detect_route_leaks_in_announcements(
    announcements_df,
    asrelprob,
    threshold
):
    """
    Leak - 
    """
    return detect_route_leaks_vectorized(announcements_df, asrelprob, threshold)


def analyze_leak_surface(
    asn,
    start_time,
    end_time,
    pathprob_file: str | None = None,
    threshold = DEFAULT_LEAK_THRESHOLD,
    target_asns: List[str] | None = None,
    max_leaks: int = 5000,
):
    """
    Analyze route leaks for specified AS and time period.

    Args:
        asn: Primary AS number
        start_time: Start time string (format: "YYYY-MM-DD HH:MM")
        end_time: End time string (format: "YYYY-MM-DD HH:MM")
        pathprob_file: Optional path to pathprob.txt file
        threshold: Leak detection threshold (default: 0.4)
        target_asns: List of AS numbers to filter by. Only messages containing these ASNs will be analyzed.
                    If None, analyzes all messages (backward compatibility).
        max_leaks: Maximum number of leaks to return (default: 5000). 0 means no limit.

    Returns:
        Dictionary with leak analysis results
    """
    from data.updates_loader import get_updates_streaming
    
    # Validate the request BEFORE doing any work. Without this, swapped
    # arguments (asn passed in a time slot) surface as a confusing
    # "invalid time format" for the ASN value, and an inverted window is
    # accepted and scans nothing. Reject both explicitly.
    try:
        asn_clean, start_dt, end_dt = validate_detection_request(
            asn, start_time, end_time, asn_label="asn"
        )
    except InputValidationError as exc:
        logger.error(f"[leak] rejected request: {exc}")
        return wrap(DetectionType.LEAK, {
            "success": False,
            "asn": str(asn),
            "analysis_period": f"{start_time} to {end_time}",
            "error": str(exc),
            "route_leaks": [],
            "leak_count": 0,
            "total_detected": 0,
            "data_available": False,
            "no_data_reason": "invalid_request",
            "invalid_request": True,
            "anomalies_detected": False,
            "anomaly_count": 0,
        }, asn=str(asn)).to_dict()

    # Normalize target ASNs
    if target_asns is None:
        target_asns = [asn_clean]
    else:
        target_asns = [str(a).replace('AS', '').replace('as', '') for a in target_asns]
        if asn_clean not in target_asns:
            target_asns.append(asn_clean)

    logger.info(f"Route leak detection: filtering for AS paths containing: {target_asns}")

    try:
        start_dt = _parse_time_window(start_time)
        end_dt = _parse_time_window(end_time)
    except Exception as e:
        logger.error(f"Invalid time format for leak analysis: {e}")
        return wrap(DetectionType.LEAK, {
            "success": False,
            "asn": asn_clean,
            "analysis_period": f"{start_time} to {end_time}",
            "error": f"Invalid time format: {e}",
            "route_leaks": [],
            "leak_count": 0,
            "data_available": False,
            "no_data_reason": "invalid_time_format",
            "anomalies_detected": False,
            "anomaly_count": 0,
        }, asn=asn_clean).to_dict()

    if pathprob_file is None:
        pathprob_file = find_pathprob_file()
        
        if pathprob_file is None:
            return wrap(DetectionType.LEAK, {
                "success": False,
                "asn": asn_clean,
                "analysis_period": f"{start_time} to {end_time}",
                "error": "PathProb file not found",
                "message": "Please provide pathprob_file path or ensure pathprob.txt exists. Check logs for search locations.",
                "search_paths": [str(p) for p in PATHPROB_SEARCH_PATHS],
                "route_leaks": [],
                "leak_count": 0,
                "data_available": False,
                "no_data_reason": "pathprob_file_missing",
                "anomalies_detected": False,
                "anomaly_count": 0,
            }, asn=asn_clean).to_dict()
    
    asrelprob = _read_prob(pathprob_file)
    
    if len(asrelprob) == 0:
        logger.error("Failed to load AS relationship probabilities")
        return wrap(DetectionType.LEAK, {
            "success": False,
            "asn": asn_clean,
            "analysis_period": f"{start_time} to {end_time}",
            "error": "Failed to load AS relationship probabilities",
            "route_leaks": [],
            "leak_count": 0,
            "data_available": False,
            "no_data_reason": "asrelprob_load_failed",
            "anomalies_detected": False,
            "anomaly_count": 0,
        }, asn=asn_clean).to_dict()
    
    # （ES）
    all_leaks = []
    
    # ========== ES，CSV ==========
    # The Elasticsearch fast path was removed 2026-10-05: it called
    # get_leak_candidates_es / convert_es_records_to_dataframe, neither of
    # which exists in this module, so the block could only ever raise
    # NameError if re-enabled. Detection reads the CSV stream below.
    logger.info(f"Using CSV streaming for leak detection (max_leaks={max_leaks})")

    # target AS
    target_asns_set = set(target_asns)

    all_leaks = []
    total_announcements = 0
    filtered_announcements = 0
    chunk_count = 0
    total_leak_count = 0  # 

    for df_chunk in get_updates_streaming(start_dt, end_dt, workers=MAX_WORKERS, io_busy_threshold=IO_BUSY_THRESHOLD, auto_download=True):
        chunk_count += 1

        if df_chunk is None or df_chunk.is_empty():
            continue

        # ，
        announcements = df_chunk.filter(pl.col('A/W') == 'A').select(['as-path', 'prefix', 'timestamp', 'origin'])
        del df_chunk  # chunk
        gc.collect()

        if announcements.is_empty():
            continue

        total_announcements += len(announcements)

        # ========== Bug: ASN（）==========
        filtered_ann = announcements
        if target_asns:
            # Pre-split as-path into a list column so .list.contains() can
            # do exact-token matching.
            _has_split = "as_path_tokens" in announcements.columns
            if not _has_split:
                announcements = announcements.with_columns(
                    pl.col("as-path").str.split(by=" ").alias("as_path_tokens")
                )
            mask = None
            for _target_asn in target_asns_set:
                m = announcements["as_path_tokens"].list.contains(_target_asn)
                mask = m if mask is None else (mask | m)
            filtered_ann = announcements.filter(mask)
            filtered_announcements += len(filtered_ann)

        if filtered_ann.is_empty():
            del announcements, filtered_ann
            gc.collect()
            continue

        # Detect leaks in this filtered chunk
        chunk_leaks = detect_route_leaks_vectorized(filtered_ann, asrelprob, threshold, max_leaks=0)
        total_leak_count += len(chunk_leaks)

        # max_leaks，leaks
        if max_leaks > 0 and len(all_leaks) >= max_leaks:
            del announcements, filtered_ann, chunk_leaks
            gc.collect()
            logger.warning(f"Reached max_leaks limit ({max_leaks}), stopping early")
            break

        # leaks，
        remaining_slots = max_leaks - len(all_leaks) if max_leaks > 0 else len(chunk_leaks)
        if remaining_slots > 0:
            all_leaks.extend(chunk_leaks[:remaining_slots])

        if chunk_leaks:
            logger.info(f"Chunk {chunk_count}: detected {len(chunk_leaks)} route leaks (total: {total_leak_count})")

        # 
        del announcements, filtered_ann, chunk_leaks
        gc.collect()

    logger.info(f"Route leak analysis completed (CSV): {total_leak_count} leaks detected from {filtered_announcements} filtered announcements (out of {total_announcements} total)")

    # BUG (2026-10-05): `route_leaks` / `leak_count` are capped by max_leaks,
    # while `total_detected` holds the real count. Downstream consumers
    # (routing_impl -> report payload, report_agent's leak table, llm_reasoning)
    # read `leak_count` or `len(route_leaks)`, i.e. the CAP, so a run that found
    # 20849 leaks was reported as "5000 route leaks" with no indication that the
    # number was a truncation limit rather than a measurement. That reads as
    # overwhelming evidence when it is actually an artefact of the limit.
    #
    # Publish the truncation state explicitly so a consumer can say
    # ">=5000 (truncated)" instead of asserting 5000.
    truncated = bool(max_leaks > 0 and total_leak_count > len(all_leaks))
    if truncated:
        logger.warning(
            f"leak results TRUNCATED: reporting {len(all_leaks)} of "
            f"{total_leak_count} detected (max_leaks={max_leaks})"
        )

    return wrap(DetectionType.LEAK, {
        "success": True,
        "asn": asn_clean,
        "analysis_period": f"{start_time} to {end_time}",
        "pathprob_file": pathprob_file,
        "threshold": threshold,
        "target_asns": target_asns,
        "asrel_count": len(asrelprob),
        "route_leaks": all_leaks,
        "leak_count": len(all_leaks),
        "total_detected": total_leak_count,  # true count, uncapped
        "truncated": truncated,
        "truncation_limit": max_leaks if truncated else None,
        "total_announcements": total_announcements,
        "filtered_announcements": filtered_announcements,
        "data_source": "csv_streaming",
        "analysis_timestamp": datetime.now().isoformat(),
        # Unified schema fields
        "data_available": True,
        "no_data_reason": "",
        "anomalies_detected": total_leak_count > 0,
        "anomaly_count": total_leak_count,
    }, asn=asn_clean).to_dict()


def detect_route_leaks_streaming(
    announcements_df,
    asrelprob,
    pathprob_file,
    threshold
):
    if asrelprob is None:
        if pathprob_file is None:
            pathprob_file = find_pathprob_file()
        
        if pathprob_file is None or not os.path.exists(pathprob_file):
            logger.warning("PathProb file not found, skipping route leak detection")
            return []
        
        asrelprob = _read_prob(pathprob_file)
        if len(asrelprob) == 0:
            logger.warning("Failed to load AS relationship probabilities")
            return []
    
    # Detect leaks
    leaks = detect_route_leaks_in_announcements(announcements_df, asrelprob, threshold)
    
    if leaks:
        logger.info(f"Detected {len(leaks)} route leaks")
    
    return leaks


def check_pathprob_integration():
    """
    Check PathProb integration status.

    Returns:
        bool: True if PathProb is properly integrated, False otherwise
    """
    print("=" * 70)
    print("PathProb Integration Checker")
    print("=" * 70)
    print()

    print("1. Checking PathProb_AE installation...")
    pathprob_ae_path = Path(PATHPROB_AE_ROOT)
    if pathprob_ae_path.exists():
        print(f"   ✓ PathProb_AE found at: {pathprob_ae_path}")

        infer_script = pathprob_ae_path / "infer_prob" / "asrel_prob.py"
        if infer_script.exists():
            print(f"   ✓ Inference script found: {infer_script}")
        else:
            print(f"   ✗ Inference script missing: {infer_script}")
    else:
        print(f"   ✗ PathProb_AE not found at: {pathprob_ae_path}")
        print(f"     Expected location: /data/PathProb_AE")

    print()

    print("2. Searching for pathprob.txt file...")
    pathprob_file = find_pathprob_file()

    if pathprob_file:
        print(f"   ✓ Found pathprob.txt at: {pathprob_file}")

        file_size = os.path.getsize(pathprob_file)
        print(f"   ✓ File size: {file_size:,} bytes ({file_size / 1024 / 1024:.2f} MB)")

        try:
            with open(pathprob_file, 'r') as f:
                line_count = sum(1 for _ in f)
            print(f"   ✓ File is readable, contains {line_count:,} lines")
        except Exception as e:
            print(f"   ✗ Error reading file: {e}")
    else:
        print("   ✗ pathprob.txt not found in any search location")
        print()
        print("   Searched locations:")
        for i, search_path in enumerate(PATHPROB_SEARCH_PATHS, 1):
            exists = "✓" if search_path.exists() else "✗"
            print(f"     {i}. {exists} {search_path}")

    print()

    if not pathprob_file:
        print("3. How to generate pathprob.txt:")
        print()
        print("   Option 1: Use PathProb_AE to generate the file")
        print(f"   {''.join([' '] * 3)}cd {PATHPROB_AE_ROOT}")
        print(f"   {''.join([' '] * 3)}python3 infer_prob/asrel_prob.py \\")
        print(f"   {''.join([' '] * 5)}--path_dir <path_to_as_paths> \\")
        print(f"   {''.join([' '] * 5)}--print_dir <output_directory>")
        print()
        print("   Option 2: Set environment variable")
        print(f"   {''.join([' '] * 3)}export PATHPROB_FILE=/path/to/pathprob.txt")
        print()
        print("   Option 3: Place file in default location")
        default_location = PROJECT_ROOT / "data" / "pathprob" / "pathprob.txt"
        print(f"   {''.join([' '] * 3)}mkdir -p {default_location.parent}")
        print(f"   {''.join([' '] * 3)}cp /path/to/pathprob.txt {default_location}")
        print()
    else:
        print("3. Integration Status: ✓ READY")
        print()
        print("   PathProb is properly integrated. Route leak detection should work.")

    print()
    print("=" * 70)

    return pathprob_file is not None


def extract_as_paths_from_bgp_data(start_time, end_time, output_dir, min_path_length=2):
    """
    Extract AS paths from BGP data for PathProb analysis.

    Args:
        start_time: Start time (datetime or str)
        end_time: End time (datetime or str)
        output_dir: Output directory path
        min_path_length: Minimum AS path length to include

    Returns:
        str: Path to output file, or None if failed
    """
    from collections import Counter

    try:
        start_dt = _parse_time_window(start_time)
        end_dt = _parse_time_window(end_time)
    except Exception as e:
        logger.error(f"Invalid time format: {e}")
        return None

    from data.updates_loader import get_updates_streaming

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    path_counter = Counter()

    total_updates = 0
    chunk_count = 0

    logger.info(f"Extracting AS paths from {start_time} to {end_time}")

    from config import MAX_WORKERS, IO_BUSY_THRESHOLD
    for df_chunk in get_updates_streaming(start_dt, end_dt, workers=MAX_WORKERS, io_busy_threshold=IO_BUSY_THRESHOLD, auto_download=True):
        chunk_count += 1

        if df_chunk is None or df_chunk.is_empty():
            continue

        # ，
        announcements = df_chunk.filter(pl.col('A/W') == 'A').select(['as-path'])
        del df_chunk  # chunk
        gc.collect()

        if announcements.is_empty():
            del announcements
            gc.collect()
            continue

        total_updates += len(announcements)

        # Process using polars iteration
        for row in announcements.iter_rows(named=True):
            as_path_str = str(row.get('as-path', ''))
            if not as_path_str:
                continue

            path = _parse_as_path(as_path_str)

            if len(path) < min_path_length:
                continue

            path_str = '|'.join(path)
            path_counter[path_str] += 1

        # chunk
        del announcements
        gc.collect()

        if chunk_count % 10 == 0:
            logger.info(f"Processed {chunk_count} chunks, {total_updates} updates, {len(path_counter)} unique paths")

    logger.info(f"Extraction complete: {total_updates} updates, {len(path_counter)} unique paths")

    output_file = output_path / "as_paths.txt"
    with open(output_file, 'w', encoding='utf-8') as f:
        for path, count in path_counter.items():
            if count > 1:
                f.write(f"{path} {count}\n")
            else:
                f.write(f"{path}\n")

    logger.info(f"AS paths saved to: {output_file}")
    logger.info(f"Total paths: {len(path_counter)}")
    logger.info(f"Total path occurrences: {sum(path_counter.values())}")

    return str(output_file)


__all__ = [
    "analyze_leak_surface",
    "detect_route_leaks_in_announcements",
    "detect_route_leaks_streaming",
    "find_pathprob_file",
    "check_pathprob_integration",
    "extract_as_paths_from_bgp_data",
    "DEFAULT_LEAK_THRESHOLD"
]
