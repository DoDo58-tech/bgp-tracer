"""
Elasticsearch查询工具模块
用于BGP劫持和泄漏检测的ES加速查询
"""
import sys
import os
from typing import List, Dict, Any, Optional, Set
from datetime import datetime
from pathlib import Path

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger
from config import ES_HOST, ES_INDEX_NAME, ES_ENABLED


class ESQueryHelper:
    """Elasticsearch查询辅助类"""
    
    def __init__(self, host: str = None, index_name: str = None):
        self.host = host or ES_HOST
        self.index_name = index_name or ES_INDEX_NAME
        self.client = None
        self._connect()
    
    def _connect(self):
        """连接到Elasticsearch"""
        try:
            import requests
            self.client = requests.Session()
            resp = self.client.get(f"{self.host}", timeout=10)
            if resp.status_code == 200:
                logger.info(f"Connected to Elasticsearch at {self.host}")
            else:
                logger.warning(f"ES connection returned {resp.status_code}")
                self.client = None
        except Exception as e:
            logger.warning(f"Failed to connect to Elasticsearch: {e}")
            self.client = None
    
    def is_available(self) -> bool:
        """检查ES是否可用"""
        return self.client is not None
    
    def get_leak_candidates(
        self,
        target_asn: str,
        start_time: datetime,
        end_time: datetime,
        batch_size: int = 10000
    ) -> List[Dict[str, Any]]:
        """
        获取Leak检测候选宣告：AS路径包含目标AS的宣告
        
        Args:
            target_asn: 目标AS号
            start_time: 开始时间
            end_time: 结束时间
            batch_size: 每批获取的文档数
            
        Returns:
            宣告列表，每条包含: as-path, prefix, timestamp, origin等
        """
        if not self.is_available():
            logger.warning("ES not available for leak candidate query")
            return []
        
        try:
            import requests
            
            # 转换为字符串时间
            start_str = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
            end_str = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")
            
            # 尝试将AS号转为整数
            try:
                asn_int = int(target_asn)
            except ValueError:
                asn_int = 0
            
            logger.info(f"[ES] Querying leak candidates: AS{asn_int}, {start_str} to {end_str}")
            
            # 构建查询：时间范围 + Announcement + AS路径包含目标ASN
            query = {
                "query": {
                    "bool": {
                        "filter": [
                            {
                                "range": {
                                    "timestamp": {
                                        "gte": start_str,
                                        "lte": end_str
                                    }
                                }
                            },
                            # ES中aw字段表示A/W
                            {"term": {"aw": "A"}}
                        ]
                    }
                },
                "_source": [
                    "as_path", "as_path_list", "prefix", "timestamp",
                    "peer_as", "peer_ip", "origin", "type", "aw"
                ],
                "sort": [{"timestamp": {"order": "asc"}}],
                "size": batch_size
            }
            
            # 如果as_path_list字段可用，使用terms查询
            # 否则使用as_path的wildcard查询
            if asn_int > 0:
                # 尝试使用as_path_list数组查询
                array_query = {
                    "query": {
                        "bool": {
                            "filter": [
                                {"range": {"timestamp": {"gte": start_str, "lte": end_str}}},
                                {"term": {"aw": "A"}},
                                {"term": {"as_path_list": asn_int}}
                            ]
                        }
                    },
                    "_source": ["as_path", "as_path_list", "prefix", "timestamp", "peer_as", "peer_ip", "origin"],
                    "sort": [{"timestamp": {"order": "asc"}}],
                    "size": batch_size
                }
                
                resp = self.client.post(
                    f"{self.host}/{self.index_name}/_search",
                    json=array_query,
                    timeout=60
                )
                
                if resp.status_code == 200:
                    results = resp.json()
                    hits = results.get('hits', {}).get('hits', [])
                    total = results.get('hits', {}).get('total', {})
                    
                    if isinstance(total, dict):
                        total_count = total.get('value', 0)
                    else:
                        total_count = total
                    
                    if total_count > batch_size:
                        # 需要scroll查询获取所有结果
                        return self._scroll_query(array_query, total_count, batch_size)
                    
                    logger.info(f"[ES] Found {len(hits)} leak candidates (total: {total_count})")
                    return [hit['_source'] for hit in hits]
                else:
                    logger.warning(f"[ES] Array query failed ({resp.status_code}), trying alternative")
            
            # Fallback: 使用as_path的wildcard查询
            # 注意: as_path是keyword类型，wildcard查询需要考虑格式
            # as_path格式如: "206499 34549 2914 3491 984"
            wildcard_query = {
                "query": {
                    "bool": {
                        "filter": [
                            {"range": {"timestamp": {"gte": start_str, "lte": end_str}}},
                            {"term": {"aw": "A"}},
                            # 使用regexp匹配AS路径中包含目标ASN
                            {"regexp": {"as_path": f".*\\b{asn_int}\\b.*"}}
                        ]
                    }
                },
                "_source": ["as_path", "as_path_list", "prefix", "timestamp", "peer_as", "peer_ip", "origin"],
                "sort": [{"timestamp": {"order": "asc"}}],
                "size": batch_size
            }
            
            resp = self.client.post(
                f"{self.host}/{self.index_name}/_search",
                json=wildcard_query,
                timeout=60
            )
            
            if resp.status_code == 200:
                results = resp.json()
                hits = results.get('hits', {}).get('hits', [])
                total = results.get('hits', {}).get('total', {})
                
                if isinstance(total, dict):
                    total_count = total.get('value', 0)
                else:
                    total_count = total
                
                if total_count > batch_size:
                    return self._scroll_query(wildcard_query, total_count, batch_size)
                
                logger.info(f"[ES] Found {len(hits)} leak candidates via wildcard (total: {total_count})")
                return [hit['_source'] for hit in hits]
            else:
                logger.error(f"[ES] Wildcard query failed: {resp.status_code} - {resp.text[:200]}")
                return []
                
        except Exception as e:
            logger.error(f"[ES] Error querying leak candidates: {e}")
            return []
    
    def get_hijack_candidates(
        self,
        target_asn: str,
        target_prefixes: Set[str],
        start_time: datetime,
        end_time: datetime,
        batch_size: int = 10000
    ) -> List[Dict[str, Any]]:
        """
        获取Hijack检测候选宣告：
        1. AS路径包含目标AS，或
        2. prefix属于目标AS
        
        Args:
            target_asn: 目标AS号
            target_prefixes: 目标AS拥有的prefix集合
            start_time: 开始时间
            end_time: 结束时间
            batch_size: 每批获取的文档数
            
        Returns:
            宣告列表
        """
        if not self.is_available():
            logger.warning("ES not available for hijack candidate query")
            return []
        
        try:
            import requests
            
            start_str = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
            end_str = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")
            
            try:
                asn_int = int(target_asn)
            except ValueError:
                asn_int = 0
            
            # 构建查询：时间范围 + Announcement + (AS路径包含目标ASN OR prefix在目标列表中)
            query = {
                "query": {
                    "bool": {
                        "should": [
                            # 条件1: AS路径包含目标AS
                            {"term": {"as_path_list": asn_int}},
                            # 条件2: prefix属于目标AS
                            {"terms": {"prefix": list(target_prefixes)[:1000]}}  # ES terms限制1000个
                        ],
                        "minimum_should_match": 1,
                        "filter": [
                            {"range": {"timestamp": {"gte": start_str, "lte": end_str}}},
                            {"term": {"aw": "A"}}
                        ]
                    }
                },
                "_source": [
                    "as_path", "as_path_list", "prefix", "timestamp",
                    "peer_as", "peer_ip", "origin", "type", "aw"
                ],
                "sort": [{"timestamp": {"order": "asc"}}],
                "size": batch_size
            }
            
            resp = self.client.post(
                f"{self.host}/{self.index_name}/_search",
                json=query,
                timeout=60
            )
            
            if resp.status_code == 200:
                results = resp.json()
                hits = results.get('hits', {}).get('hits', [])
                total = results.get('hits', {}).get('total', {})
                
                if isinstance(total, dict):
                    total_count = total.get('value', 0)
                else:
                    total_count = total
                
                logger.info(f"[ES] Found {len(hits)} hijack candidates (total: {total_count})")
                
                if total_count > batch_size:
                    return self._scroll_query(query, total_count, batch_size)
                
                return [hit['_source'] for hit in hits]
            else:
                logger.error(f"[ES] Hijack query failed: {resp.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"[ES] Error querying hijack candidates: {e}")
            return []
    
    def _scroll_query(
        self,
        base_query: Dict,
        total_count: int,
        batch_size: int,
        scroll_time: str = "5m"
    ) -> List[Dict[str, Any]]:
        """
        使用scroll API获取大量结果
        
        Args:
            base_query: 基础查询
            total_count: 总结果数
            batch_size: 每批大小
            scroll_time: scroll超时时间
            
        Returns:
            所有结果列表
        """
        try:
            import requests
            
            all_results = []
            remaining = total_count
            scroll_id = None
            
            # 第一次查询
            resp = self.client.post(
                f"{self.host}/{self.index_name}/_search?scroll={scroll_time}",
                json=base_query,
                timeout=60
            )
            
            if resp.status_code != 200:
                logger.error(f"[ES] Scroll query failed: {resp.status_code}")
                return []
            
            results = resp.json()
            hits = results.get('hits', {}).get('hits', [])
            scroll_id = results.get('_scroll_id')
            all_results.extend([hit['_source'] for hit in hits])
            remaining -= len(hits)
            
            logger.info(f"[ES] Scroll progress: {len(all_results)}/{total_count}")
            
            # 继续scroll直到获取所有结果
            while remaining > 0 and scroll_id and hits:
                resp = self.client.post(
                    f"{self.host}/_search/scroll",
                    json={"scroll": scroll_time, "scroll_id": scroll_id},
                    timeout=60
                )
                
                if resp.status_code != 200:
                    logger.warning(f"[ES] Scroll failed: {resp.status_code}")
                    break
                
                results = resp.json()
                hits = results.get('hits', {}).get('hits', [])
                scroll_id = results.get('_scroll_id')
                
                if not hits:
                    break
                
                all_results.extend([hit['_source'] for hit in hits])
                remaining -= len(hits)
                
                if len(all_results) % 50000 == 0:
                    logger.info(f"[ES] Scroll progress: {len(all_results)}/{total_count}")
            
            # 清理scroll上下文
            if scroll_id:
                try:
                    self.client.delete(
                        f"{self.host}/_search/scroll",
                        json={"scroll_id": scroll_id}
                    )
                except:
                    pass
            
            logger.info(f"[ES] Scroll complete: {len(all_results)} total results")
            return all_results
            
        except Exception as e:
            logger.error(f"[ES] Error in scroll query: {e}")
            return []
    
    def get_as_pair_frequency(
        self,
        as_pair: str,
        start_time: datetime,
        end_time: datetime
    ) -> Dict[str, Any]:
        """
        获取AS对的连接频率（用于验证fake connection）
        
        Args:
            as_pair: AS对，格式 "as1|as2"
            start_time: 开始时间
            end_time: 结束时间
            
        Returns:
            频率信息，包含count, total, ratio等
        """
        if not self.is_available():
            return {"count": 0, "total": 0, "ratio": 0.0, "available": False}
        
        try:
            import requests
            
            start_str = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
            end_str = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")
            
            # 查询包含该AS对的宣告数量
            query = {
                "query": {
                    "bool": {
                        "filter": [
                            {"range": {"timestamp": {"gte": start_str, "lte": end_str}}},
                            {"term": {"aw": "A"}},
                            {"term": {"as_pairs": as_pair}}
                        ]
                    }
                }
            }
            
            resp = self.client.post(
                f"{self.host}/{self.index_name}/_count",
                json=query,
                timeout=30
            )
            
            if resp.status_code == 200:
                count = resp.json().get("count", 0)
                
                # 查询该时间段的总宣告数
                total_query = {
                    "query": {
                        "bool": {
                            "filter": [
                                {"range": {"timestamp": {"gte": start_str, "lte": end_str}}},
                                {"term": {"aw": "A"}}
                            ]
                        }
                    }
                }
                
                total_resp = self.client.post(
                    f"{self.host}/{self.index_name}/_count",
                    json=total_query,
                    timeout=30
                )
                
                total = 0
                if total_resp.status_code == 200:
                    total = total_resp.json().get("count", 0)
                
                ratio = count / total if total > 0 else 0.0
                
                return {
                    "count": count,
                    "total": total,
                    "ratio": ratio,
                    "available": True
                }
            else:
                return {"count": 0, "total": 0, "ratio": 0.0, "available": False}
                
        except Exception as e:
            logger.error(f"[ES] Error querying AS pair frequency: {e}")
            return {"count": 0, "total": 0, "ratio": 0.0, "available": False}


# 全局实例
_es_query_helper: Optional[ESQueryHelper] = None


def get_es_query_helper() -> Optional[ESQueryHelper]:
    """获取ES查询辅助类实例（单例）"""
    global _es_query_helper
    
    if _es_query_helper is None and ES_ENABLED:
        _es_query_helper = ESQueryHelper()
    
    return _es_query_helper if _es_query_helper and _es_query_helper.is_available() else None


def is_es_available() -> bool:
    """检查ES是否可用"""
    helper = get_es_query_helper()
    return helper is not None and helper.is_available()


def get_leak_candidates_es(
    target_asn: str,
    start_time: datetime,
    end_time: datetime
) -> List[Dict[str, Any]]:
    """
    从ES获取Leak检测候选宣告
    
    Args:
        target_asn: 目标AS号
        start_time: 开始时间
        end_time: 结束时间
        
    Returns:
        宣告列表，如果ES不可用则返回空列表
    """
    helper = get_es_query_helper()
    if helper is None:
        return []
    
    return helper.get_leak_candidates(target_asn, start_time, end_time)


def get_hijack_candidates_es(
    target_asn: str,
    target_prefixes: Set[str],
    start_time: datetime,
    end_time: datetime
) -> List[Dict[str, Any]]:
    """
    从ES获取Hijack检测候选宣告
    
    Args:
        target_asn: 目标AS号
        target_prefixes: 目标AS的prefix集合
        start_time: 开始时间
        end_time: 结束时间
        
    Returns:
        宣告列表，如果ES不可用则返回空列表
    """
    helper = get_es_query_helper()
    if helper is None:
        return []
    
    return helper.get_hijack_candidates(target_asn, target_prefixes, start_time, end_time)


def convert_es_records_to_dataframe(records: List[Dict[str, Any]]) -> 'pd.DataFrame':
    """
    将ES记录转换为DataFrame格式（匹配现有代码的列名）
    
    Args:
        records: ES查询结果列表
        
    Returns:
        Pandas DataFrame
    """
    import pandas as pd
    
    if not records:
        return pd.DataFrame()
    
    # 转换ES字段到CSV格式
    converted = []
    for record in records:
        # ES字段名到CSV字段名的映射
        converted_record = {
            'prefix': record.get('prefix', ''),
            'as-path': record.get('as_path', ''),
            'timestamp': record.get('timestamp', ''),
            'origin': record.get('origin', ''),
            'peer_as': record.get('peer_as', ''),
            'peer_ip': record.get('peer_ip', ''),
            'type': record.get('type', 'BGP4MP'),
            'A/W': record.get('aw', 'A'),
        }
        converted.append(converted_record)
    
    df = pd.DataFrame(converted)
    return df


__all__ = [
    'ESQueryHelper',
    'get_es_query_helper',
    'is_es_available',
    'get_leak_candidates_es',
    'get_hijack_candidates_es',
    'convert_es_records_to_dataframe'
]
