#!/usr/bin/env python3
"""
将BGP updates消息导入到Elasticsearch

用法:
    python scripts/import_updates_to_es.py --start "2024-12-26 00:00" --end "2025-01-02 00:00"
    python scripts/import_updates_to_es.py --start "2024-12-26 00:00" --end "2025-01-02 00:00" --force
"""
import sys
import os
import argparse
import hashlib
from datetime import datetime, timedelta
from pathlib import Path

# 添加项目根目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from data.updates_loader import get_updates_streaming
from utils.elasticsearch_client import ESClient, get_es_client
from utils.logger import logger
from config import ES_ENABLED


def extract_as_pairs(as_path: str) -> list:
    """从AS路径中提取AS对"""
    import pandas as pd
    if not as_path or pd.isna(as_path):
        return []
    
    segments = str(as_path).strip().split()
    if len(segments) < 2:
        return []
    
    pairs = []
    for i in range(len(segments) - 1):
        pairs.append(f"{segments[i]}-{segments[i+1]}")
    
    return pairs


def generate_document_id(timestamp: str, peer_as: str, prefix: str, as_path: str) -> str:
    """
    生成唯一的文档ID（用于去重）
    
    基于: timestamp + peer_as + prefix + as_path
    """
    # 组合唯一标识
    unique_str = f"{timestamp}|{peer_as}|{prefix}|{as_path}"
    
    # 生成MD5哈希作为ID
    doc_id = hashlib.md5(unique_str.encode()).hexdigest()
    return doc_id


def _convert_dataframe_to_docs_vectorized(df, file_source: str = None) -> list:
    """
    向量化转换DataFrame为ES文档（比iterrows快10-50倍）
    
    Args:
        df: DataFrame with announcements
        file_source: 源文件名
    
    Returns:
        ES文档列表
    """
    import pandas as pd
    
    if df.empty:
        return []
    
    n_rows = len(df)
    
    # 向量化处理时间戳（兼容字符串和数字格式）
    try:
        # 尝试作为数字时间戳（Unix timestamp）
        timestamps = pd.to_datetime(df['timestamp'].astype(float), unit='s', errors='coerce')
    except (ValueError, TypeError):
        # 如果失败，尝试作为字符串解析
        timestamps = pd.to_datetime(df['timestamp'], errors='coerce')
    timestamp_strs = timestamps.dt.strftime('%Y-%m-%dT%H:%M:%S').fillna('').astype(str).values
    
    # 向量化提取字段
    as_paths = df['as-path'].fillna('').astype(str).values
    peer_as_str = df['peer_as'].fillna('').astype(str).values
    prefix_str = df['prefix'].fillna('').astype(str).values
    peer_ip_str = df['peer_ip'].fillna('').astype(str).values
    origin_str = df['origin'].fillna('').astype(str).values
    next_hop_str = df['next-hop'].fillna('').astype(str).values
    type_str = df['A/W'].fillna('A').astype(str).values
    
    # 批量提取AS路径数组（向量化）
    as_path_arrays = [path.strip().split() if path else [] for path in as_paths]
    
    # 批量提取AS对（优化：使用join减少字符串操作）
    as_pairs_list = []
    for as_path in as_paths:
        if not as_path:
            as_pairs_list.append([])
            continue
        segments = as_path.strip().split()
        if len(segments) < 2:
            as_pairs_list.append([])
            continue
        # 使用join比循环f-string快
        pairs = ['-'.join(segments[i:i+2]) for i in range(len(segments) - 1)]
        as_pairs_list.append(pairs)
    
    # 批量生成文档ID（优化：直接使用字符串拼接，避免Series操作）
    timestamp_for_id = df['timestamp'].astype(str).values
    # 使用列表推导式 + map，比pandas apply快
    unique_strings = [
        f"{ts}|{asn}|{pfx}|{path}"
        for ts, asn, pfx, path in zip(timestamp_for_id, peer_as_str, prefix_str, as_paths)
    ]
    doc_ids = [hashlib.md5(s.encode()).hexdigest() for s in unique_strings]
    
    # 处理可选字段（向量化）
    local_pref_vals = None
    if 'local-pref' in df.columns:
        local_pref_series = pd.to_numeric(df['local-pref'], errors='coerce')
        local_pref_vals = local_pref_series.values
    
    med_vals = None
    if 'med' in df.columns:
        med_series = pd.to_numeric(df['med'], errors='coerce')
        med_vals = med_series.values
    
    communities_vals = None
    if 'communities' in df.columns:
        communities_vals = df['communities'].fillna('').astype(str).values
    
    # 批量构建文档（使用列表推导式）
    docs = []
    for i in range(n_rows):
        doc = {
            "_id": doc_ids[i],
            "timestamp": timestamp_strs[i],
            "type": type_str[i],
            "peer_ip": peer_ip_str[i],
            "peer_as": peer_as_str[i],
            "prefix": prefix_str[i],
            "as_path": as_paths[i],
            "as_path_array": as_path_arrays[i],
            "as_pairs": as_pairs_list[i],
            "origin": origin_str[i],
            "next_hop": next_hop_str[i],
        }
        
        # 可选字段
        if local_pref_vals is not None and pd.notna(local_pref_vals[i]):
            doc["local_pref"] = int(local_pref_vals[i])
        
        if med_vals is not None and pd.notna(med_vals[i]):
            doc["med"] = int(med_vals[i])
        
        if communities_vals is not None and communities_vals[i]:
            doc["communities"] = communities_vals[i]
        
        if file_source:
            doc["file_source"] = file_source
        
        docs.append(doc)
    
    return docs


def convert_to_es_document(row, file_source: str = None) -> dict:
    """
    将DataFrame行转换为ES文档
    
    Args:
        row: DataFrame行
        file_source: 源文件名
    
    Returns:
        ES文档字典
    """
    import pandas as pd
    
    # 解析时间戳
    try:
        timestamp = datetime.fromtimestamp(float(row['timestamp']))
    except (ValueError, TypeError):
        timestamp = datetime.now()
    
    # 提取AS路径数组
    as_path = str(row.get('as-path', ''))
    as_path_array = as_path.strip().split() if as_path else []
    
    # 提取AS对
    as_pairs = extract_as_pairs(as_path)
    
    doc = {
        "timestamp": timestamp.isoformat(),
        "type": str(row.get('A/W', 'A')),
        "peer_ip": str(row.get('peer_ip', '')),
        "peer_as": str(row.get('peer_as', '')),
        "prefix": str(row.get('prefix', '')),
        "as_path": as_path,
        "as_path_array": as_path_array,
        "as_pairs": as_pairs,
        "origin": str(row.get('origin', '')),
        "next_hop": str(row.get('next-hop', '')),
    }
    
    # 可选字段
    if 'local-pref' in row and pd.notna(row['local-pref']):
        try:
            doc["local_pref"] = int(row['local-pref'])
        except (ValueError, TypeError):
            pass
    
    if 'med' in row and pd.notna(row['med']):
        try:
            doc["med"] = int(row['med'])
        except (ValueError, TypeError):
            pass
    
    if 'communities' in row and pd.notna(row['communities']):
        doc["communities"] = str(row['communities'])
    
    if file_source:
        doc["file_source"] = file_source
    
    return doc


def import_updates_to_es(
    start_time: datetime,
    end_time: datetime,
    force_recreate: bool = False,
    batch_size: int = 1000,
    disable_refresh: bool = True,
):
    """
    将BGP updates导入到Elasticsearch
    
    Args:
        start_time: 开始时间
        end_time: 结束时间
        force_recreate: 是否强制重新创建索引
        batch_size: 批量导入大小
    """
    if not ES_ENABLED:
        logger.error("Elasticsearch is not enabled.")
        logger.error("Please set ES_ENABLED=true:")
        logger.error("  export ES_ENABLED=true")
        logger.error("Or run: python scripts/check_es_connection.py")
        return
    
    # 获取ES客户端
    es_client = get_es_client()
    if not es_client:
        logger.error("Failed to get ES client")
        return
    
    try:
        # 创建索引
        logger.info(f"Creating/checking index: {es_client.index_name}")
        es_client.create_index(force=force_recreate)
        
        # 禁用刷新以加速导入（可选）
        if disable_refresh:
            try:
                es_client.client.indices.put_settings(
                    index=es_client.index_name,
                    body={"refresh_interval": "-1"}
                )
                logger.info("✅ Disabled index refresh for faster import")
            except Exception as e:
                logger.warning(f"Failed to disable refresh: {e}")
        
        # 统计信息
        total_docs = 0
        total_files = 0
        
        # 遍历所有更新文件
        logger.info(f"Importing updates from {start_time} to {end_time}")
        
        batch_docs = []
        for df_chunk in get_updates_streaming(start_time, end_time):
            if df_chunk is None or df_chunk.empty:
                continue
            
            total_files += 1
            
            # 只处理Announcement消息
            announcements = df_chunk[df_chunk['A/W'] == 'A']
            if announcements.empty:
                continue
            
            # 获取文件源（如果有）
            file_source = None
            if hasattr(df_chunk, 'attrs') and 'file_source' in df_chunk.attrs:
                file_source = df_chunk.attrs['file_source']
            
            # 向量化转换为ES文档（大幅提升性能）
            file_docs = _convert_dataframe_to_docs_vectorized(announcements, file_source)
            batch_docs.extend(file_docs)
            
            # 批量导入（累积到batch_size再提交，减少ES调用次数）
            if len(batch_docs) >= batch_size:
                batch_to_index = batch_docs[:batch_size]
                es_client.bulk_index(batch_to_index, batch_size=batch_size)
                total_docs += len(batch_to_index)
                batch_docs = batch_docs[batch_size:]
                # 减少日志频率（每5万条或每10个文件输出一次）
                if total_docs % 50000 == 0 or total_files % 10 == 0:
                    logger.info(f"Progress: {total_docs:,} documents indexed, {total_files} files processed")
        
        # 导入剩余的文档
        if batch_docs:
            es_client.bulk_index(batch_docs, batch_size=batch_size)
            total_docs += len(batch_docs)
        
        logger.info(f"✅ Import completed: {total_docs:,} documents indexed from {total_files} files")
        
        # 恢复刷新设置
        if disable_refresh:
            try:
                es_client.client.indices.put_settings(
                    index=es_client.index_name,
                    body={"refresh_interval": "30s"}
                )
                logger.info("✅ Restored index refresh interval")
            except Exception as e:
                logger.warning(f"Failed to restore refresh: {e}")
        
        # 刷新索引
        es_client.client.indices.refresh(index=es_client.index_name)
        logger.info("Index refreshed")
        
    except Exception as e:
        logger.error(f"Import failed: {e}", exc_info=True)
        raise
    finally:
        es_client.close()


def main():
    parser = argparse.ArgumentParser(description="Import BGP updates to Elasticsearch")
    parser.add_argument("--start", required=True, help="Start time (YYYY-MM-DD HH:MM)")
    parser.add_argument("--end", required=True, help="End time (YYYY-MM-DD HH:MM)")
    parser.add_argument("--force", action="store_true", help="Force recreate index")
    parser.add_argument("--batch-size", type=int, default=1000, help="Batch size for indexing (default: 1000, recommend: 5000 for faster import)")
    parser.add_argument("--enable-refresh", action="store_true", help="Keep index refresh enabled (slower but safer)")
    
    args = parser.parse_args()
    
    # 解析时间
    try:
        start_time = datetime.strptime(args.start, "%Y-%m-%d %H:%M")
        end_time = datetime.strptime(args.end, "%Y-%m-%d %H:%M")
    except ValueError:
        logger.error("Invalid time format. Use: YYYY-MM-DD HH:MM")
        return
    
    if start_time >= end_time:
        logger.error("Start time must be before end time")
        return
    
    # 导入数据
    import_updates_to_es(
        start_time=start_time,
        end_time=end_time,
        force_recreate=args.force,
        batch_size=args.batch_size,
        disable_refresh=not args.enable_refresh,  # 默认禁用刷新以加速
    )


if __name__ == "__main__":
    import pandas as pd
    main()

