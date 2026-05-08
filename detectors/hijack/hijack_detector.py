import os
import sys
import gc
import json
import pandas as pd
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
project_root = "/data/bgp_tracer"
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from utils.logger import logger
from detectors.hijack.hijack_utils import remove_consecutive_duplicates
from detectors.hijack import hijack_cache_manager
from detectors.hijack.hijack_prefix_processor import get_target_prefixes_batch, build_prefix_trie, is_subnet_of_trie
from detectors.hijack.hijack_detector_core import detect_origin_hijacks, detect_forge_hijacks, analyze_connection_frequency
from detectors.hijack.hijack_analyzer import aggregate_anomalies, save_alert_messages

from data.updates_loader import get_updates_streaming
from data.prefix2as_loader import process_prefix2as
from data.asorg_loader import process_asorg
from data.asrel_loader import process_asrel
from config import MAX_WORKERS, IO_BUSY_THRESHOLD


def load_full_day_bgp_data(start_time, end_time):
    try:
        # Extract the date from start_time to load the complete day
        target_date = start_time.date() if hasattr(start_time, 'date') else pd.to_datetime(start_time).date()
        day_start = datetime.combine(target_date, datetime.min.time())
        day_end = datetime.combine(target_date, datetime.max.time())

        logger.info(f"Loading complete day BGP data for {target_date} (from {day_start} to {day_end})")

        full_day_data = []
        total_chunks = 0
        total_announcements = 0

        for df_chunk in get_updates_streaming(day_start, day_end, workers=MAX_WORKERS, io_busy_threshold=IO_BUSY_THRESHOLD, auto_download=True):
            total_chunks += 1
            if df_chunk is None or df_chunk.empty:
                continue

            # 早期筛选并只保留必要列，减少内存占用
            announcements = df_chunk[df_chunk['A/W'] == 'A'][['prefix', 'as-path', 'timestamp']].copy()
            del df_chunk  # 立即释放原始chunk
            gc.collect()

            if announcements.empty:
                continue

            announcements['as-path'] = announcements['as-path'].apply(remove_consecutive_duplicates)
            announcements['date'] = pd.to_datetime(announcements['timestamp']).dt.date.astype(str)

            chunk_size = len(announcements)
            total_announcements += chunk_size
            full_day_data.extend(announcements.to_dict('records'))

            # 每处理5个chunk就清理一次内存
            if total_chunks % 5 == 0:
                gc.collect()
                logger.info(f"Loaded {total_announcements:,} announcements from {total_chunks} chunks so far...")

        logger.info(f"Successfully loaded {len(full_day_data):,} BGP announcements for complete day {target_date}")
        result_df = pd.DataFrame(full_day_data)
        del full_day_data
        gc.collect()
        return result_df

    except Exception as e:
        logger.error(f"Error loading full day BGP data: {e}")
        return pd.DataFrame()


def detect_hijacks_streaming(
    start_time,
    end_time,
    target_as,
    validate_with_updates = False,
    save_alerts = True,
    update_workers = 1,
    io_busy_threshold = 85,
    skip_forge_detection = False,  # 控制是否跳过forge hijack检测
):
    try:
        logger.info(f"Starting hijack detection for AS{target_as} from {start_time} to {end_time} (skip_forge: {skip_forge_detection})")

        batch_results = detect_hijacks_batch(
            start_time=start_time,
            end_time=end_time,
            target_as_list=[target_as],
            validate_with_updates=validate_with_updates,
            save_alerts=save_alerts,
            update_workers=update_workers,
            io_busy_threshold=io_busy_threshold,
            skip_forge_detection=skip_forge_detection
        )

        # CRITICAL: Ensure batch_results is always a dict
        if batch_results is None:
            batch_results = {"success": False, "error": "batch_results is None", "results_by_as": {}}

        # Try both integer and string key (batch_results uses strings, but target_as might be integer)
        results_by_as = batch_results.get("results_by_as", {})
        
        # Normalize the key - results_by_as uses string keys
        as_key_str = str(target_as)
        as_key_int = int(target_as) if str(target_as).isdigit() else target_as
        
        # Check which key exists in results_by_as
        if as_key_str in results_by_as:
            actual_key = as_key_str
        elif as_key_int in results_by_as:
            actual_key = as_key_int
        else:
            actual_key = None
        
        if batch_results.get("success") and actual_key is not None:
            as_result = results_by_as[actual_key]
            # Convert origin_hijacked/forge_hijacked for downstream compatibility
            # CRITICAL: Add 'success' key to ensure routing_agent can detect success properly
            result = {
                "success": True,  # MUST include success=True for routing_agent to process this result
                "origin_hijacked": as_result.get("origin_hijacked", []),
                "forge_hijacked": as_result.get("forge_hijacked", []),
                "total_announcements": as_result.get("total_announcements", 0),
                "batch_mode": False,
                "aggregated_alerts": as_result.get("aggregated_alerts", [])
            }
            return result
        
        # If we reach here, something went wrong
        return {
            "success": False,
            "error": "Detection failed - condition not met",
            "asn": target_as,
            "analysis_period": f"{start_time} to {end_time}"
        }

    except Exception as e:
        logger.error(f"Hijack detection failed for AS{target_as}: {e}")
        return {
            "success": False,
            "error": str(e),
            "asn": target_as,
            "analysis_period": f"{start_time} to {end_time}"
        }


def detect_hijacks(
    start_time,
    end_time,
    target_as,
    use_streaming = True,
    validate_with_updates = False,
    save_alerts = True,
    update_workers = 1,
    io_busy_threshold = 85,
    skip_forge_detection = False,  # 控制是否跳过forge hijack检测（MITM）
):
    return detect_hijacks_streaming(
        start_time=start_time,
        end_time=end_time,
        target_as=target_as,
        validate_with_updates=validate_with_updates,
        save_alerts=save_alerts,
        update_workers=update_workers,
        io_busy_threshold=io_busy_threshold,
        skip_forge_detection=skip_forge_detection,
    )


def detect_hijacks_batch(
    start_time,
    end_time,
    target_as_list,
    validate_with_updates = False,
    save_alerts = True,
    update_workers = 1,
    io_busy_threshold = 85,
    skip_forge_detection = False,  # 控制是否跳过forge hijack检测（MITM）
    use_csv_for_origin = True,     # 强制使用CSV做Origin Hijack检测（不使用ES）
):
    """
    批量劫持检测主函数。
    
    重要：Origin Hijack检测始终使用本地CSV文件，不使用ES。
    只有Forge Hijack（MITM）检测在enable时才会使用ES查询历史连接频率。
    
    Args:
        skip_forge_detection: True=跳过Forge Hijack检测（不使用ES）, False=启用Forge检测
        use_csv_for_origin: True=Origin Hijack始终用CSV（推荐）
    """
    logger.info(f"Starting BATCH hijack detection for {len(target_as_list)} AS from {start_time} to {end_time}")
    logger.info(f"Configuration: skip_forge={skip_forge_detection}, use_csv_for_origin={use_csv_for_origin}")
    
    cleaned_as_list = []
    for asn in target_as_list:
        asn_clean = str(asn).replace('AS', '').replace('as', '')
        cleaned_as_list.append(asn_clean)
    
    logger.info(f"Target AS list: {', '.join(['AS' + asn for asn in cleaned_as_list])}")

    # 加载AS关系数据
    asrel_result = process_asrel(start_time)
    if isinstance(asrel_result, str) and asrel_result and os.path.exists(asrel_result):
        with open(asrel_result, 'r', encoding='utf-8') as f:
            as_relationships_data = json.load(f)
        logger.info("Successfully loaded AS relationship data")
    else:
        logger.error("Failed to load AS relationship data")
        as_relationships_data = {}

    # 加载前缀映射
    prefix2as_path = process_prefix2as(start_time)
    if prefix2as_path:
        with open(prefix2as_path, 'r', encoding='utf-8') as f:
            prefix_to_as = json.load(f)
        logger.info(f"Loaded prefix-to-AS mappings from {prefix2as_path}")
    else:
        logger.error("Failed to load prefix-to-AS mappings")
        prefix_to_as = {}

    # 构建目标前缀集合
    prefixes_by_as = get_target_prefixes_batch(cleaned_as_list, prefix_to_as)
    union_target_prefixes = set().union(*prefixes_by_as.values()) if prefixes_by_as else set()
    cleaned_as_set = set(cleaned_as_list)

    # 构建前缀Trie用于子网匹配
    prefix_trie = build_prefix_trie(union_target_prefixes)

    # 预加载全天数据（仅在需要Forge检测时）
    full_day_data = None
    if validate_with_updates and not skip_forge_detection:
        logger.info("Pre-loading full day BGP data for forge hijack detection...")
        full_day_data = load_full_day_bgp_data(start_time, end_time)
        logger.info(f"Loaded {len(full_day_data) if full_day_data is not None else 0} announcements for full day analysis")

    # 前缀所有者映射
    prefix_owner_map = {}
    for asn, pref_set in prefixes_by_as.items():
        for p in pref_set:
            prefix_owner_map.setdefault(p, []).append(asn)
    
    for asn in cleaned_as_list:
        prefix_count = len(prefixes_by_as.get(asn, set()))
        logger.info(f"AS{asn}: {prefix_count} target prefixes")
    
    # 初始化结果
    batch_results = {}
    for asn in cleaned_as_list:
        batch_results[asn] = {
            "origin_hijacked": [],    # 目标AS被劫持
            "origin_hijacking": [],   # 目标AS劫持别人
            "forge_hijack": [],      # MITM攻击（目标AS被攻击）
            "forge_hijacking": [],    # MITM攻击（目标AS发起攻击）
            "total_announcements": 0,
        }
    
    total_processed_rows = 0
    chunk_count = 0
    memory_peaks = []
    processing_times = []
    
    # ========== 使用CSV流式处理进行Origin Hijack检测 ==========
    # 重要：始终使用本地CSV文件，不依赖ES
    logger.info(f"Using CSV streaming for Origin Hijack detection (forge detection: {'skipped' if skip_forge_detection else 'enabled'})")
    for asn, pref_set in prefixes_by_as.items():
        for p in pref_set:
            prefix_owner_map.setdefault(p, []).append(asn)
    
    for asn in cleaned_as_list:
        prefix_count = len(prefixes_by_as.get(asn, set()))
        logger.info(f"AS{asn}: {prefix_count} target prefixes")
    
    batch_results = {}
    for asn in cleaned_as_list:
        batch_results[asn] = {
            "origin_hijacked": [],    # 目标AS被劫持
            "origin_hijacking": [],   # 目标AS劫持别人
            "forge_hijack": [],      # MITM攻击（目标AS被攻击）
            "forge_hijacking": [],    # MITM攻击（目标AS发起攻击）
            "total_announcements": 0,
        }
    
    total_processed_rows = 0
    chunk_count = 0
    memory_peaks = []
    processing_times = []
    
    # ========== 使用CSV流式处理进行Origin Hijack检测 ==========
    # 重要：始终使用本地CSV文件，不依赖ES
    logger.info(f"Using CSV streaming for Origin Hijack detection (forge detection: {'skipped' if skip_forge_detection else 'enabled'})")

    for df_chunk in get_updates_streaming(start_time, end_time, workers=MAX_WORKERS, io_busy_threshold=IO_BUSY_THRESHOLD, auto_download=True):
        import time
        chunk_start_time = time.time()

        chunk_count += 1

        if df_chunk is None or df_chunk.empty:
            logger.info(f"Chunk {chunk_count} is empty, skipping")
            continue

        chunk_rows = len(df_chunk)
        logger.info(f"Processing chunk {chunk_count} with {chunk_rows} rows")

        # 早期筛选：只保留 Announce 消息并只保留必要列
        announcements = df_chunk[df_chunk['A/W'] == 'A'][['prefix', 'as-path', 'timestamp']].copy()
        if announcements.empty:
            logger.info(f"Chunk {chunk_count} has no announcements, skipping")
            continue

        # 立即释放原始chunk
        del df_chunk
        gc.collect()

        # 处理as-path（向量化）
        announcements['as-path'] = announcements['as-path'].apply(remove_consecutive_duplicates)

        # ========== 向量化过滤（优化apply(axis=1)）==========
        # 条件1: prefix精确匹配
        mask1 = announcements['prefix'].isin(union_target_prefixes)
        
        # 条件2: prefix是子网（使用trie）
        mask2 = announcements['prefix'].apply(
            lambda p: is_subnet_of_trie(p, prefix_trie) if p else False
        )
        
        # 条件3: AS路径包含目标AS（向量化操作）
        mask3 = announcements['as-path'].str.split().apply(
            lambda tokens: bool(set(tokens) & cleaned_as_set) if tokens else False
        )
        
        # 三条件OR合并
        announcements = announcements[mask1 | mask2 | mask3]
        
        if announcements.empty:
            logger.info(f"Chunk {chunk_count}: no relevant announcements after filtering")
            continue

        # ========== 优化：使用向量化方法替代iterrows ==========
        # 策略：按AS分组处理，而不是逐行处理
        
        # 为每个AS创建过滤后的DataFrame（使用向量化）
        for asn in cleaned_as_list:
            asn_str = str(asn)
            
            # 条件：该行的AS路径包含当前AS
            as_mask = announcements['as-path'].str.split().apply(
                lambda tokens: asn_str in tokens if tokens else False
            )
            
            df_asn = announcements[as_mask].copy()
            
            if df_asn.empty:
                continue
            
            batch_results[asn]["total_announcements"] += len(df_asn)
            
            # Origin Hijack检测（始终执行）
            if not df_asn.empty:
                if skip_forge_detection:
                    # 跳过forge检测，直接进行origin检测
                    df_asn['connection_frequency_suspicious'] = False
                    df_asn['has_fake_connect'] = False
                    df_asn['fake_connections'] = '[]'
                    analyzed_df = df_asn
                else:
                    # Forge Hijack检测（使用本地数据，不依赖ES）
                    forge_alerts, analyzed_df = detect_forge_hijacks(
                        df_asn,
                        as_relationships_data,
                        asn,
                        hijack_cache_manager,
                        full_day_data=full_day_data,
                        prefix_to_as=prefix_to_as
                    )
                    
                    for alert in forge_alerts:
                        if isinstance(alert, dict):
                            batch_results[asn]["forge_hijack"].append(alert)

                if not analyzed_df.empty:
                    # Origin Hijack检测（按类型分开存储）
                    origin_hijacks = detect_origin_hijacks(analyzed_df, prefix_to_as, target_as=asn)
                    if origin_hijacks:
                        for hijack in origin_hijacks:
                            hijack_type = hijack.get('hijack_type', 'origin_hijacked')
                            if hijack_type == 'origin_hijacked':
                                # 目标AS被劫持
                                batch_results[asn]["origin_hijacked"].append(hijack)
                            elif hijack_type == 'origin_hijacking':
                                # 目标AS劫持别人
                                batch_results[asn]["origin_hijacking"].append(hijack)
                            # 其他类型不处理

        # 关键：处理完一个chunk后立即释放所有相关内存
        del announcements
        gc.collect()

        chunk_time = time.time() - chunk_start_time
        processing_times.append(chunk_time)

        # 每个chunk都报告内存使用
        import psutil
        memory_mb = psutil.Process().memory_info().rss / 1024 / 1024
        memory_peaks.append(memory_mb)
        avg_time = sum(processing_times[-min(10, len(processing_times)):]) / len(processing_times[-min(10, len(processing_times)):])
        logger.info(f"Chunk {chunk_count}: {avg_time:.2f}s avg, {memory_mb:.1f}MB memory")

        total_processed_rows += chunk_rows
        logger.info(f"Chunk {chunk_count}: Processed {chunk_rows} rows for {len(cleaned_as_list)} AS")

    all_fake_connection_groups = {}
    if validate_with_updates:
        logger.info("Collecting fake connections for batch validation...")
        for asn in cleaned_as_list:
            forge_alerts = batch_results[asn]["forge_hijack"]
            for alert in forge_alerts:
                if isinstance(alert, dict):
                    fake_conn = alert.get('fake_connection', '')
                    prefix = alert.get('prefix', '')
                    timestamp = alert.get('timestamp', '')
                    as_path = alert.get('as-path', '')

                    if fake_conn and prefix:
                        key = (asn, prefix, fake_conn)
                        if key not in all_fake_connection_groups:
                            all_fake_connection_groups[key] = {
                                'prefix': prefix,
                                'fake_connection': fake_conn,
                                'first_seen': str(timestamp),
                                'last_seen': str(timestamp),
                                'as_path': as_path,
                                'paths': [as_path],
                                'announcement_count': 1
                            }
                        else:
                            all_fake_connection_groups[key]['last_seen'] = max(
                                all_fake_connection_groups[key]['last_seen'],
                                str(timestamp)
                            )
                            all_fake_connection_groups[key]['announcement_count'] += 1
                            if as_path not in all_fake_connection_groups[key]['paths']:
                                all_fake_connection_groups[key]['paths'].append(as_path)

    batch_connection_frequencies = {}
    if validate_with_updates and all_fake_connection_groups:
        logger.info(f"Validating {len(all_fake_connection_groups)} fake connections with full day data...")

        unique_fake_connections = {}
        for key, group in all_fake_connection_groups.items():
            validation_key = (group['prefix'], group['fake_connection'])
            if validation_key not in unique_fake_connections:
                unique_fake_connections[validation_key] = group
            else:
                existing = unique_fake_connections[validation_key]
                existing['last_seen'] = max(existing['last_seen'], group['last_seen'])
                existing['announcement_count'] += group['announcement_count']
                if group['as_path'] not in existing['paths']:
                    existing['paths'].append(group['as_path'])

        validated_connections = {}
        for validation_key, group in unique_fake_connections.items():
            try:
                fake_conn = group['fake_connection']
                # Use the last_seen timestamp of this connection as the end of the ES 7-day window
                end_ts = group.get('last_seen', start_time.strftime('%Y-%m-%d'))
                frequency_result = analyze_connection_frequency(
                    fake_conn,
                    start_time.strftime('%Y-%m-%d'),
                    full_day_data,
                    end_timestamp=end_ts,
                )
                validated_connections[validation_key] = frequency_result
            except Exception as e:
                logger.warning(f"Error validating connection {validation_key}: {e}")
                validated_connections[validation_key] = {'is_suspicious': True, 'error': str(e)}

        logger.info(f"Validation completed: {len(validated_connections)} unique connections checked")

        for key, group in all_fake_connection_groups.items():
            validation_key = (group['prefix'], group['fake_connection'])
            if validation_key in validated_connections:
                result = validated_connections[validation_key]
                batch_connection_frequencies[key] = {
                    'is_suspicious': result.get('is_suspicious', True),
                    'frequency_ratio': result.get('frequency_ratio', 0),
                    'count': result.get('count', 0),
                    'total_updates': result.get('total_updates', 0),
                    'threshold_used': result.get('threshold_used', 0.001)
                }

    if validate_with_updates and batch_connection_frequencies:
        logger.info("Re-validating forge hijacks with batch-computed frequencies...")
        for asn in cleaned_as_list:
            for alert in batch_results[asn]["forge_hijacked"] + batch_results[asn]["forge_hijack"]:
                fake_conn = alert.get('fake_connection', '')
                prefix = alert.get('prefix', '')
                if fake_conn and prefix:
                    key = (asn, prefix, fake_conn)
                    freq_data = batch_connection_frequencies.get(key, {})
                    frequency_ratio = freq_data.get('frequency_ratio', 0)
                    is_suspicious = freq_data.get('is_suspicious', True)

                    alert['connection_frequency_past_week'] = freq_data.get('count', 0)
                    alert['frequency_ratio'] = frequency_ratio
                    alert['is_legitimate'] = not is_suspicious
                    alert['detection_status'] = 'legitimate_connection' if not is_suspicious else 'illegal_connection'
                    alert['validation_threshold'] = freq_data.get('threshold_used', 0.001)
    
    asorg_path = process_asorg(start_time)
    
    final_results = {}
    for asn in cleaned_as_list:
        result_data = batch_results[asn]
        
        # 所有异常（包括被攻击和攻击别人）
        all_anomalies = (
            result_data["origin_hijacked"]     # 目标AS被劫持
            + result_data["origin_hijacking"]  # 目标AS劫持别人
            + result_data["forge_hijacked"]    # MITM攻击（被攻击）
            + result_data["forge_hijacking"]   # MITM攻击（发起攻击）
        )
        aggregated_alerts = aggregate_anomalies(all_anomalies)
        
        final_results[asn] = {
            "success": True,
            "asn": asn,
            "analysis_period": f"{start_time} to {end_time}",
            # 目标AS被劫持
            "origin_hijacked": result_data["origin_hijacked"],
            # 目标AS劫持别人
            "origin_hijacking": result_data["origin_hijacking"],
            # Forge/MITM检测
            "forge_hijacked": result_data["forge_hijacked"],
            "forge_hijacking": result_data["forge_hijacking"],
            # 汇总
            "all_anomalies": all_anomalies,
            "aggregated_alerts": aggregated_alerts,
            "prefix2as_file": prefix2as_path,
            "asorg_file": asorg_path,
            "target_prefixes": list(prefixes_by_as[asn]),
            "total_announcements": result_data["total_announcements"],
            "analysis_timestamp": datetime.now().isoformat(),
        }
        
        logger.info(f"AS{asn} Detection: {len(result_data['origin_hijacked'])} origin hijacked, "
                   f"{len(result_data['origin_hijacking'])} origin hijacking, "
                   f"{len(result_data['forge_hijacked'])} forge hijacked, "
                   f"{len(result_data['forge_hijacking'])} forge hijacking")

        if save_alerts:
            # Convert datetime objects to strings for save_alert_messages
            start_time_str = start_time.strftime("%Y-%m-%d %H:%M") if hasattr(start_time, 'strftime') else str(start_time)
            end_time_str = end_time.strftime("%Y-%m-%d %H:%M") if hasattr(end_time, 'strftime') else str(end_time)

            save_alert_messages(
                asn,
                start_time_str,
                end_time_str,
                result_data["forge_hijacked"],
                result_data["origin_hijacked"]
            )
    
    logger.info(f"Batch detection completed for {len(cleaned_as_list)} AS")

    if processing_times:
        total_time = sum(processing_times)
        avg_chunk_time = total_time / len(processing_times)
        total_chunks = len(processing_times)

        logger.info(f"🎯 Performance Optimization Results:")
        logger.info(f"   Processed {total_chunks} chunks, {total_processed_rows:,} total rows")
        logger.info(f"   Average chunk time: {avg_chunk_time:.2f}s")
        logger.info(f"   Total processing time: {total_time:.1f}s")
        logger.info(f"   Processing rate: {total_processed_rows/total_time:.0f} rows/sec")

        if memory_peaks:
            avg_memory = sum(memory_peaks) / len(memory_peaks)
            max_memory = max(memory_peaks)
            logger.info(f"   Memory usage: {avg_memory:.1f}MB avg, {max_memory:.1f}MB peak")

    return {
        "success": True,
        "batch_mode": True,
        "as_count": len(cleaned_as_list),
        "results_by_as": final_results,
        "analysis_period": f"{start_time} to {end_time}",
        "analysis_timestamp": datetime.now().isoformat(),
        "data_source": "csv_streaming",
        "performance_stats": {
            "total_chunks": len(processing_times) if 'processing_times' in locals() else 0,
            "total_rows": total_processed_rows if 'total_processed_rows' in locals() else 0,
            "avg_chunk_time": sum(processing_times)/len(processing_times) if processing_times else 0,
            "memory_peak_mb": max(memory_peaks) if memory_peaks else 0
        }
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

    print(f"\n{'='*60}")
    print(f"Detection results for AS{args.asn}")
    print(f"Period: {args.start} to {args.end}")
    print(f"{'='*60}")

    if results.get("success"):
        print(f"\n📊 Detection Summary:")
        print(f"  origin_hijack:    {len(results.get('origin_hijack', []))}")
        print(f"  forge_hijack:      {len(results.get('forge_hijack', []))}")
        print(f"  Total announcements: {results.get('total_announcements', 0)}")

        output_dir = Path("/data/bgp_tracer/results/json")
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        asn_clean = args.asn.replace('AS', '').replace('as', '')
        json_file = output_dir / f"hijack_results_AS{asn_clean}_{timestamp}.json"

        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)

        print(f"Results saved to: {json_file}")
    else:
        print(f"❌ Detection failed: {results.get('error', 'Unknown error')}")
