"""
Elasticsearch版本的BGP updates查询接口
提供与get_updates_streaming兼容的ES查询功能
"""
import pandas as pd
from typing import Iterator, Optional
from datetime import datetime
from utils.elasticsearch_client import get_es_client
from utils.logger import logger
from config import ES_ENABLED


def get_updates_from_es(
    start_time: datetime,
    end_time: datetime,
    as_pairs: Optional[list] = None,
    peer_as: Optional[str] = None,
    prefix: Optional[str] = None,
    as_path_contains: Optional[list] = None,
    size: int = 10000,
    scroll: str = "5m",
) -> Iterator[pd.DataFrame]:
    """
    从Elasticsearch查询BGP updates
    
    Args:
        start_time: 开始时间
        end_time: 结束时间
        as_pairs: AS对列表（用于假连接查询）
        peer_as: 对等AS号
        prefix: 前缀
        as_path_contains: AS路径中包含的AS号列表
        size: 每次返回的文档数
        scroll: 滚动查询时间
    
    Yields:
        DataFrame chunks
    """
    if not ES_ENABLED:
        logger.warning("Elasticsearch is not enabled, falling back to file-based query")
        return
    
    es_client = get_es_client()
    if not es_client:
        logger.warning("Failed to get ES client, falling back to file-based query")
        return
    
    try:
        # 构建查询
        must_clauses = []
        
        # 时间范围查询
        must_clauses.append({
            "range": {
                "timestamp": {
                    "gte": start_time.isoformat(),
                    "lte": end_time.isoformat()
                }
            }
        })
        
        # AS对查询（用于假连接验证）
        if as_pairs:
            must_clauses.append({
                "terms": {
                    "as_pairs": as_pairs
                }
            })
        
        # 对等AS查询
        if peer_as:
            must_clauses.append({
                "term": {
                    "peer_as": str(peer_as)
                }
            })
        
        # 前缀查询
        if prefix:
            must_clauses.append({
                "term": {
                    "prefix": prefix
                }
            })
        
        # AS路径包含查询
        if as_path_contains:
            for asn in as_path_contains:
                must_clauses.append({
                    "term": {
                        "as_path_array": str(asn)
                    }
                })
        
        query = {
            "bool": {
                "must": must_clauses
            }
        }
        
        # 执行搜索
        response = es_client.search(query, size=size, scroll=scroll)
        
        scroll_id = response.get("_scroll_id")
        total = response["hits"]["total"]["value"]
        logger.info(f"Found {total} documents matching query")
        
        # 处理第一批结果
        hits = response["hits"]["hits"]
        while hits:
            # 转换为DataFrame
            docs = [hit["_source"] for hit in hits]
            df = _convert_to_dataframe(docs)
            
            if not df.empty:
                yield df
            
            # 如果没有更多结果，退出
            if len(hits) < size:
                break
            
            # 继续滚动查询
            if scroll_id:
                response = es_client.client.scroll(
                    scroll_id=scroll_id,
                    scroll=scroll
                )
                hits = response["hits"]["hits"]
                scroll_id = response.get("_scroll_id")
            else:
                break
        
        # 清除scroll
        if scroll_id:
            es_client.client.clear_scroll(scroll_id=scroll_id)
    
    except Exception as e:
        logger.error(f"ES query failed: {e}", exc_info=True)
        raise


def _convert_to_dataframe(docs: list) -> pd.DataFrame:
    """将ES文档转换为DataFrame"""
    if not docs:
        return pd.DataFrame()
    
    # 转换文档格式
    rows = []
    for doc in docs:
        row = {
            "type": doc.get("type", ""),
            "timestamp": doc.get("timestamp", ""),
            "A/W": doc.get("type", "A"),
            "peer_ip": doc.get("peer_ip", ""),
            "peer_as": doc.get("peer_as", ""),
            "prefix": doc.get("prefix", ""),
            "as-path": doc.get("as_path", ""),
            "origin": doc.get("origin", ""),
            "next-hop": doc.get("next_hop", ""),
        }
        
        if "local_pref" in doc:
            row["local-pref"] = doc["local_pref"]
        if "med" in doc:
            row["med"] = doc["med"]
        if "communities" in doc:
            row["communities"] = doc["communities"]
        
        rows.append(row)
    
    return pd.DataFrame(rows)


def count_as_pair_frequency(
    start_time: datetime,
    end_time: datetime,
    as_pairs: list,
) -> dict:
    """
    统计AS对的出现频率（用于假连接验证）
    
    Args:
        start_time: 开始时间
        end_time: 结束时间
        as_pairs: AS对列表
    
    Returns:
        {as_pair: frequency} 字典
    """
    if not ES_ENABLED:
        logger.warning("Elasticsearch is not enabled")
        return {}
    
    es_client = get_es_client()
    if not es_client:
        logger.warning("Failed to get ES client")
        return {}
    
    try:
        # 构建查询
        query = {
            "bool": {
                "must": [
                    {
                        "range": {
                            "timestamp": {
                                "gte": start_time.isoformat(),
                                "lte": end_time.isoformat()
                            }
                        }
                    },
                    {
                        "terms": {
                            "as_pairs": as_pairs
                        }
                    }
                ]
            }
        }
        
        # 聚合查询
        aggs = {
            "as_pair_frequency": {
                "terms": {
                    "field": "as_pairs",
                    "size": len(as_pairs) * 2  # 确保包含所有AS对
                }
            }
        }
        
        response = es_client.aggregate(query, aggs, size=0)
        
        # 提取结果
        buckets = response["aggregations"]["as_pair_frequency"]["buckets"]
        frequency_map = {bucket["key"]: bucket["doc_count"] for bucket in buckets}
        
        # 确保所有AS对都有值（即使为0）
        result = {as_pair: 0 for as_pair in as_pairs}
        result.update(frequency_map)
        
        return result
    
    except Exception as e:
        logger.error(f"Count AS pair frequency failed: {e}", exc_info=True)
        return {}

