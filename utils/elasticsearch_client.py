"""
Elasticsearch客户端工具类
用于BGP updates消息的存储和查询
"""
import os
from typing import Optional, Dict, Any, List
from datetime import datetime
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
from utils.logger import logger
from config import (
    ES_HOST, ES_PORT, ES_USER, ES_PASSWORD, ES_USE_SSL, 
    ES_VERIFY_CERTS, ES_INDEX_NAME, ES_ENABLED
)


class ESClient:
    """Elasticsearch客户端封装类"""
    
    def __init__(
        self,
        host: str = None,
        port: int = None,
        username: str = None,
        password: str = None,
        use_ssl: bool = None,
        verify_certs: bool = None,
        index_name: str = None,
    ):
        """
        初始化ES客户端
        
        Args:
            host: ES主机地址
            port: ES端口
            username: 用户名（可选）
            password: 密码（可选）
            use_ssl: 是否使用SSL
            verify_certs: 是否验证证书
            index_name: 索引名称
        """
        self.host = host or ES_HOST
        self.port = port or ES_PORT
        self.username = username or ES_USER
        self.password = password or ES_PASSWORD
        self.use_ssl = use_ssl if use_ssl is not None else ES_USE_SSL
        self.verify_certs = verify_certs if verify_certs is not None else ES_VERIFY_CERTS
        self.index_name = index_name or ES_INDEX_NAME
        
        self.client = None
        self._connect()
    
    def _connect(self):
        """连接到Elasticsearch"""
        try:
            # 构建连接URL
            if self.use_ssl:
                scheme = "https"
            else:
                scheme = "http"
            
            # 构建hosts列表（包含scheme）
            hosts = [f"{scheme}://{self.host}:{self.port}"]
            
            # 构建连接参数
            es_config = {
                "hosts": hosts,
                "verify_certs": self.verify_certs,
            }
            
            # 如果提供了用户名和密码
            if self.username and self.password:
                es_config["basic_auth"] = (self.username, self.password)
            
            self.client = Elasticsearch(**es_config)
            
            # 测试连接
            try:
                if not self.client.ping():
                    raise ConnectionError(f"Failed to ping Elasticsearch at {self.host}:{self.port}")
            except Exception as ping_error:
                raise ConnectionError(
                    f"Failed to connect to Elasticsearch at {self.host}:{self.port}. "
                    f"Error: {ping_error}. "
                    f"Please check: 1) ES service is running, 2) ES_HOST and ES_PORT are correct, 3) Network connectivity"
                )
            
            logger.info(f"✅ Connected to Elasticsearch at {self.host}:{self.port}")
            
        except ConnectionError:
            raise
        except Exception as e:
            logger.error(f"❌ Failed to connect to Elasticsearch: {e}")
            raise ConnectionError(
                f"Failed to connect to Elasticsearch at {self.host}:{self.port}. "
                f"Error: {e}. "
                f"Please check: 1) ES service is running, 2) ES_HOST and ES_PORT are correct"
            )
    
    def create_index(self, force: bool = False):
        """
        创建索引（如果不存在）
        
        Args:
            force: 如果为True，删除已存在的索引后重新创建
        """
        if force and self.client.indices.exists(index=self.index_name):
            logger.info(f"Deleting existing index: {self.index_name}")
            self.client.indices.delete(index=self.index_name)
        
        if self.client.indices.exists(index=self.index_name):
            logger.info(f"Index {self.index_name} already exists")
            return
        
        # 定义索引映射
        mapping = {
            "mappings": {
                "properties": {
                    "timestamp": {
                        "type": "date",
                        "format": "strict_date_optional_time||epoch_millis"
                    },
                    "type": {"type": "keyword"},
                    "peer_ip": {"type": "keyword"},
                    "peer_as": {"type": "keyword"},
                    "prefix": {"type": "keyword"},
                    "as_path": {
                        "type": "text",
                        "fields": {
                            "keyword": {"type": "keyword"}
                        }
                    },
                    "as_path_array": {"type": "keyword"},  # AS路径数组
                    "as_pairs": {"type": "keyword"},  # AS对数组，用于快速查询
                    "origin": {"type": "keyword"},
                    "next_hop": {"type": "keyword"},
                    "local_pref": {"type": "integer"},
                    "med": {"type": "integer"},
                    "communities": {"type": "keyword"},
                    "file_source": {"type": "keyword"},
                }
            },
            "settings": {
                "number_of_shards": 5,
                "number_of_replicas": 1,
                "refresh_interval": "30s",  # 批量导入时减少刷新频率
            }
        }
        
        try:
            self.client.indices.create(index=self.index_name, body=mapping)
            logger.info(f"✅ Created index: {self.index_name}")
        except Exception as e:
            logger.error(f"❌ Failed to create index: {e}")
            raise
    
    def bulk_index(self, documents: List[Dict[str, Any]], batch_size: int = 1000, use_doc_id: bool = True):
        """
        批量导入文档（优化版本）
        
        Args:
            documents: 文档列表（如果包含_id字段，会用作文档ID）
            batch_size: 每批处理的文档数
            use_doc_id: 是否使用文档中的_id字段（用于去重）
        """
        if not documents:
            return
        
        # 一次性构建所有actions（比循环append快）
        actions = []
        for doc in documents:
            action = {
                "_index": self.index_name,
                "_source": doc
            }
            
            # 如果文档包含_id字段，使用它作为文档ID（用于去重）
            if use_doc_id and "_id" in doc:
                action["_id"] = doc.pop("_id")
            
            actions.append(action)
        
        # 批量提交（一次性提交所有，而不是分批）
        # 使用更大的批次可以提高ES写入效率
        try:
            # 如果actions数量很大，分批提交
            if len(actions) > batch_size:
                for i in range(0, len(actions), batch_size):
                    batch = actions[i:i+batch_size]
                    bulk(self.client, batch, request_timeout=120, max_retries=3)
            else:
                bulk(self.client, actions, request_timeout=120, max_retries=3)
        except Exception as e:
            logger.error(f"Failed to bulk index: {e}")
            raise
    
    def search(self, query: Dict[str, Any], size: int = 10000, scroll: str = None):
        """
        执行搜索查询
        
        Args:
            query: ES查询DSL
            size: 返回结果数量
            scroll: 滚动查询时间（用于大量数据）
        
        Returns:
            搜索结果
        """
        try:
            params = {
                "index": self.index_name,
                "body": {"query": query},
                "size": size
            }
            
            if scroll:
                params["scroll"] = scroll
            
            response = self.client.search(**params)
            return response
        except Exception as e:
            logger.error(f"Search failed: {e}")
            raise
    
    def aggregate(self, query: Dict[str, Any], aggs: Dict[str, Any], size: int = 0):
        """
        执行聚合查询
        
        Args:
            query: ES查询DSL
            aggs: 聚合定义
            size: 返回文档数量（0表示只返回聚合结果）
        
        Returns:
            聚合结果
        """
        try:
            response = self.client.search(
                index=self.index_name,
                body={
                    "query": query,
                    "aggs": aggs
                },
                size=size
            )
            return response
        except Exception as e:
            logger.error(f"Aggregation failed: {e}")
            raise
    
    def count(self, query: Dict[str, Any] = None):
        """
        统计匹配的文档数量
        
        Args:
            query: ES查询DSL（如果为None，统计所有文档）
        
        Returns:
            文档数量
        """
        try:
            if query is None:
                query = {"match_all": {}}
            
            response = self.client.count(
                index=self.index_name,
                body={"query": query}
            )
            return response["count"]
        except Exception as e:
            logger.error(f"Count failed: {e}")
            raise
    
    def delete_by_query(self, query: Dict[str, Any]):
        """
        根据查询删除文档
        
        Args:
            query: ES查询DSL
        """
        try:
            response = self.client.delete_by_query(
                index=self.index_name,
                body={"query": query}
            )
            logger.info(f"Deleted {response['deleted']} documents")
            return response
        except Exception as e:
            logger.error(f"Delete by query failed: {e}")
            raise
    
    def close(self):
        """关闭连接"""
        if self.client:
            self.client.close()
            logger.info("Elasticsearch connection closed")


def get_es_client() -> Optional[ESClient]:
    """
    获取ES客户端实例（如果ES已启用）
    
    Returns:
        ESClient实例或None
    """
    if not ES_ENABLED:
        logger.debug("Elasticsearch is disabled")
        return None
    
    try:
        return ESClient()
    except Exception as e:
        logger.warning(f"Failed to initialize ES client: {e}")
        return None

