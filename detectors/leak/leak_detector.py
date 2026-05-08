import os
import sys
import gc
from typing import Dict, Any, List, Tuple, Optional
from sortedcontainers import SortedDict
from pathlib import Path
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger
from config import PROJECT_ROOT, PATHPROB_SEARCH_PATHS, PATHPROB_AE_ROOT, DEFAULT_LEAK_THRESHOLD, MAX_WORKERS, IO_BUSY_THRESHOLD

# Keep DEFAULT_LEAK_THRESHOLD as alias for backward compatibility


def find_pathprob_file(pathprob_file: Optional[str] = None) -> Optional[str]:
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
                        as1, as2, p2c, p2p, c2p = parts[0], parts[1], parts[2], parts[3], parts[4]
                        probs = [float(p2c), float(p2p), float(c2p)]
                        if as1 > as2:
                            probs = [float(c2p), float(p2p), float(p2c)]
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
        as1, as2 = path[i], path[i + 1]
        link = (min(as1, as2), max(as1, as2))
        
        if link in asrelprob:
            p2c, _, c2p = asrelprob[link]
        elif link[::-1] in asrelprob:
            c2p, _, p2c = asrelprob[link[::-1]]
        else:
            continue
        
        prob = min(p2c + c2p0 - p2c * c2p0, prob)
        c2p0 = c2p
    
    # Path is a leak if probability is below threshold
    is_leak = prob < threshold
    return is_leak, prob


def detect_route_leaks_in_announcements(
    announcements_df,
    asrelprob,
    threshold
):
    leaks = []
    
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
            
            # Add additional fields if available
            for field in ['collector', 'peer-as', 'type']:
                if field in row:
                    leak_event[field] = row[field]
            
            leaks.append(leak_event)
    
    return leaks


def detect_route_leaks_vectorized(
    announcements_df,
    asrelprob,
    threshold
):
    """
    向量化leak检测 - 避免iterrows，提升性能5-10倍
    
    Args:
        announcements_df: 宣告DataFrame
        asrelprob: AS关系概率字典
        threshold: leak阈值
        
    Returns:
        leak事件列表
    """
    leaks = []
    
    if announcements_df is None or announcements_df.empty:
        return leaks
    
    if 'as-path' not in announcements_df.columns:
        logger.warning("DataFrame missing 'as-path' column")
        return leaks
    
    try:
        import pandas as pd
        
        df = announcements_df.copy()
        
        # 1. 解析AS路径（向量化）
        df['_path_list'] = df['as-path'].astype(str).apply(
            lambda x: [asn.strip() for asn in x.split() if asn.strip()]
        )
        
        # 2. 过滤短路径
        df['_path_len'] = df['_path_list'].apply(len)
        df = df[df['_path_len'] >= 2].copy()
        
        if df.empty:
            return leaks
        
        # 3. 预构建link缓存（避免重复字典查找）
        link_cache = {}
        for link, probs in asrelprob.items():
            link_cache[link] = probs
            link_cache[link[::-1]] = [probs[2], probs[1], probs[0]]
        
        # 4. 批量计算路径概率
        def compute_path_prob(path):
            if not path or len(path) < 2:
                return 1.0
            
            prob = 1.0
            c2p0 = 1.0
            
            for i in range(len(path) - 1):
                try:
                    as1, as2 = str(path[i]), str(path[i+1])
                    key = (min(as1, as2), max(as1, as2))
                    
                    if key in link_cache:
                        p2c, _, c2p = link_cache[key]
                        prob = min(p2c + c2p0 - p2c * c2p0, prob)
                        c2p0 = c2p
                except (ValueError, TypeError):
                    continue
            
            return prob
        
        df['_leak_prob'] = df['_path_list'].apply(compute_path_prob)
        
        # 5. 筛选leak
        leak_df = df[df['_leak_prob'] < threshold].copy()
        
        if leak_df.empty:
            return leaks
        
        # 6. 构建输出
        for _, row in leak_df.iterrows():
            path = row['_path_list']
            
            leak_event = {
                "timestamp": row.get('timestamp', row.get('time', '')),
                "prefix": row.get('prefix', ''),
                "as-path": row.get('as-path', ''),
                "origin-as": path[-1] if path else '',
                "leak_probability": row['_leak_prob'],
                "threshold": threshold,
                "path_length": len(path),
                "detection_method": "PathProb"
            }
            
            # 添加可选字段
            for field in ['collector', 'peer-as', 'peer_as', 'type']:
                if field in row and pd.notna(row[field]):
                    leak_event[field] = row[field]
            
            leaks.append(leak_event)
        
        logger.debug(f"Vectorized leak detection: {len(leaks)} leaks from {len(leak_df)} candidates")
        
    except Exception as e:
        logger.error(f"Error in vectorized leak detection: {e}")
        # 回退到原始逐行方法
        logger.info("Falling back to row-by-row detection")
        return detect_route_leaks_in_announcements_slow(announcements_df, asrelprob, threshold)
    
    return leaks


def detect_route_leaks_in_announcements_slow(
    announcements_df,
    asrelprob,
    threshold
):
    """
    原始逐行leak检测（用于回退）
    """
    leaks = []
    
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


def detect_route_leaks_in_announcements(
    announcements_df,
    asrelprob,
    threshold
):
    """
    Leak检测入口函数 - 优先使用向量化版本
    """
    return detect_route_leaks_vectorized(announcements_df, asrelprob, threshold)


def analyze_leak_surface(
    asn,
    start_time,
    end_time,
    pathprob_file: str | None = None,
    threshold: float = DEFAULT_LEAK_THRESHOLD,
    target_asns: List[str] | None = None,
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
    
    Returns:
        Dictionary with leak analysis results
    """
    from data.updates_loader import get_updates_streaming
    
    asn_clean = str(asn).replace('AS', '').replace('as', '')
    
    # Normalize target ASNs
    if target_asns is None:
        target_asns = [asn_clean]
    else:
        target_asns = [str(a).replace('AS', '').replace('as', '') for a in target_asns]
        if asn_clean not in target_asns:
            target_asns.append(asn_clean)
    
    logger.info(f"Route leak detection: filtering for AS paths containing: {target_asns}")
    
    # Normalize time window for streaming loader
    try:
        start_time_str = str(start_time)
        end_time_str = str(end_time)
        
        # Try with seconds first, fallback to without seconds
        try:
            start_dt = datetime.strptime(start_time_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            start_dt = datetime.strptime(start_time_str, "%Y-%m-%d %H:%M")
        
        try:
            end_dt = datetime.strptime(end_time_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            end_dt = datetime.strptime(end_time_str, "%Y-%m-%d %H:%M")
    except Exception as e:
        logger.error(f"Invalid time format for leak analysis: {e}")
        return {
            "success": False,
            "asn": asn_clean,
            "analysis_period": f"{start_time} to {end_time}",
            "error": f"Invalid time format: {e}",
        }
    
    if pathprob_file is None:
        pathprob_file = find_pathprob_file()
        
        if pathprob_file is None:
            return {
                "success": False,
                "asn": asn_clean,
                "analysis_period": f"{start_time} to {end_time}",
                "error": "PathProb file not found",
                "message": "Please provide pathprob_file path or ensure pathprob.txt exists. Check logs for search locations.",
                "search_paths": [str(p) for p in PATHPROB_SEARCH_PATHS]
            }
    
    asrelprob = _read_prob(pathprob_file)
    
    if len(asrelprob) == 0:
        logger.error("Failed to load AS relationship probabilities")
        return {
            "success": False,
            "asn": asn_clean,
            "analysis_period": f"{start_time} to {end_time}",
            "error": "Failed to load AS relationship probabilities"
        }
    
    # 预初始化（用于ES分支）
    all_leaks = []
    
    # ========== 尝试使用ES查询加速 ==========
    from utils.es_query_helper import get_leak_candidates_es, convert_es_records_to_dataframe, is_es_available
    
    if is_es_available():
        logger.info("[ES] Attempting ES query for leak detection (fast path)")
        
        # 对每个目标AS查询ES
        es_all_records = []
        for target_asn in target_asns:
            records = get_leak_candidates_es(target_asn, start_dt, end_dt)
            if records:
                es_all_records.extend(records)
                logger.info(f"[ES] Retrieved {len(records)} records for AS{target_asn}")
        
        if es_all_records:
            # 去重（同一宣告可能被多个AS查询返回）
            seen = set()
            unique_records = []
            for rec in es_all_records:
                key = (rec.get('as_path', ''), rec.get('prefix', ''), rec.get('timestamp', ''))
                if key not in seen:
                    seen.add(key)
                    unique_records.append(rec)
            
            logger.info(f"[ES] Total unique records: {len(unique_records)}")
            
            # 转换为DataFrame
            df_es = convert_es_records_to_dataframe(unique_records)
            total_announcements = len(df_es)
            filtered_announcements = total_announcements
            
            if not df_es.empty:
                # 使用向量化检测
                chunk_leaks = detect_route_leaks_vectorized(df_es, asrelprob, threshold)
                all_leaks.extend(chunk_leaks)
                
                logger.info(f"[ES] Leak detection complete: {len(chunk_leaks)} leaks from {total_announcements} records")
                
                return {
                    "success": True,
                    "asn": asn_clean,
                    "analysis_period": f"{start_time} to {end_time}",
                    "pathprob_file": pathprob_file,
                    "threshold": threshold,
                    "target_asns": target_asns,
                    "asrel_count": len(asrelprob),
                    "route_leaks": all_leaks,
                    "leak_count": len(all_leaks),
                    "total_announcements": total_announcements,
                    "filtered_announcements": filtered_announcements,
                    "data_source": "elasticsearch",
                    "analysis_timestamp": datetime.now().isoformat()
                }
        
        logger.warning("[ES] ES query returned no results, falling back to CSV streaming")
    
    # ========== CSV流式处理（降级路径）==========
    logger.info("Using CSV streaming for leak detection (slower but comprehensive)")
    
    # 预构建target AS集合用于精确匹配
    target_asns_set = set(target_asns)
    
    all_leaks = []
    total_announcements = 0
    filtered_announcements = 0
    chunk_count = 0
    
    for df_chunk in get_updates_streaming(start_dt, end_dt, workers=MAX_WORKERS, io_busy_threshold=IO_BUSY_THRESHOLD, auto_download=True):
        chunk_count += 1

        if df_chunk is None or df_chunk.empty:
            continue

        # 早期筛选，只保留必要列
        announcements = df_chunk[df_chunk['A/W'] == 'A'][['as-path', 'prefix', 'timestamp', 'origin']].copy()
        del df_chunk  # 立即释放原始chunk
        gc.collect()

        if announcements.empty:
            continue

        total_announcements += len(announcements)

        # ========== 修复Bug: 精确ASN匹配（避免子串误匹配）==========
        # 原代码: any(target_asn in str(x) for ...) 会误匹配AS1234和AS12345
        # 修复: 按空格分割后精确匹配
        def as_path_contains_asn_precise(as_path_str, target_asns_set):
            """精确ASN匹配：按空格分割后匹配"""
            if not as_path_str:
                return False
            tokens = str(as_path_str).split()
            return any(asn in tokens for asn in target_asns_set)
        
        filtered_ann = announcements.copy()
        if target_asns:
            mask = filtered_ann['as-path'].apply(
                lambda x: as_path_contains_asn_precise(x, target_asns_set)
            )
            filtered_ann = filtered_ann[mask]
            filtered_announcements += len(filtered_ann)

        if filtered_ann.empty:
            del announcements, filtered_ann
            gc.collect()
            continue

        # Detect leaks in this filtered chunk (使用向量化版本)
        chunk_leaks = detect_route_leaks_vectorized(filtered_ann, asrelprob, threshold)
        all_leaks.extend(chunk_leaks)

        if chunk_leaks:
            logger.info(f"Chunk {chunk_count}: detected {len(chunk_leaks)} route leaks from {len(filtered_ann)} filtered announcements")

        # 及时释放内存
        del announcements, filtered_ann
        gc.collect()
    
    logger.info(f"Route leak analysis completed (CSV): {len(all_leaks)} leaks detected from {filtered_announcements} filtered announcements (out of {total_announcements} total)")
    
    return {
        "success": True,
        "asn": asn_clean,
        "analysis_period": f"{start_time} to {end_time}",
        "pathprob_file": pathprob_file,
        "threshold": threshold,
        "target_asns": target_asns,
        "asrel_count": len(asrelprob),
        "route_leaks": all_leaks,
        "leak_count": len(all_leaks),
        "total_announcements": total_announcements,
        "filtered_announcements": filtered_announcements,
        "data_source": "csv_streaming",
        "analysis_timestamp": datetime.now().isoformat()
    }


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
        start_time_str = str(start_time)
        end_time_str = str(end_time)
        
        # Try with seconds first, fallback to without seconds
        try:
            start_dt = datetime.strptime(start_time_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            start_dt = datetime.strptime(start_time_str, "%Y-%m-%d %H:%M")
        
        try:
            end_dt = datetime.strptime(end_time_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            end_dt = datetime.strptime(end_time_str, "%Y-%m-%d %H:%M")
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

        if df_chunk is None or df_chunk.empty:
            continue

        # 只保留必要列，减少内存占用
        announcements = df_chunk[df_chunk['A/W'] == 'A'][['as-path']].copy()
        del df_chunk  # 立即释放原始chunk
        gc.collect()

        if announcements.empty:
            del announcements
            gc.collect()
            continue

        total_updates += len(announcements)

        for idx, row in announcements.iterrows():
            as_path_str = str(row.get('as-path', ''))
            if not as_path_str:
                continue

            path = _parse_as_path(as_path_str)

            if len(path) < min_path_length:
                continue

            path_str = '|'.join(path)
            path_counter[path_str] += 1

        # 每处理完一个chunk立即释放
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
