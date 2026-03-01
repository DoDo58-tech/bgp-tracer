# 在本机使用 Docker 启动 Elasticsearch（单节点）——快速上手

本指南用于在开发/测试服务器上通过 Docker Compose 启动单节点 Elasticsearch（方便将 `updates` 导入并测试查询）。它假定你不想对宿主系统做复杂的 ES 运维配置，仅用于本地/内网测试。

注意：示例 compose 在本地绑定到 `127.0.0.1:9200`，默认不开放到公网。生产环境请启用 TLS、认证与访问控制。

Prerequisites
- 已安装 Docker 与 Docker Compose（或 Docker 自带的 compose 插件）
- 当前用户可运行 `docker`（或使用 `sudo`）
- 有足够内存（建议至少 4GB 可分配给 ES，调整 `ES_JAVA_OPTS`）

宿主机设置（必须）
- 设置 vm.max_map_count（一次性，需 root 权限）：

```bash
sudo sysctl -w vm.max_map_count=262144
# 永久生效（可选）：
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

启动（项目根目录）：

```bash
# 启动单节点 ES（后台）
docker compose up -d

# 查看日志
docker compose logs -f elasticsearch
```

检查是否就绪：

```bash
curl -sS http://127.0.0.1:9200/
```
应返回包含 `name`、`cluster_name` 等信息的 JSON。

关于安全与端口
- Compose 文件将端口绑定为 `127.0.0.1:9200:9200`，仅本机可访问。如果需要远程访问，请修改绑定并务必开启 TLS/认证或使用 VPN。ES 内部节点通信端口 `9300` 只在集群多节点时需要暴露。

资源与性能提示
- 在 `docker-compose.yml` 中已设置 `ES_JAVA_OPTS=-Xms1g -Xmx1g`；根据主机内存调整。不要把 heap 设为超过机器一半或超过 32GB。
- 导入大量 updates 时，参考仓库 `docs/ES_IMPORT_FAQ.md` 的批量导入优化建议（禁用刷新、临时减少副本等）。

Sample project configuration (本地测试)
- 将下面配置加入到项目 `config.py`（或在运行时通过环境变量覆盖），以便项目连接本机 ES：

```python
# Elasticsearch 本地（docker）示例
ES_ENABLED = True
ES_HOST = "127.0.0.1"
ES_PORT = 9200
ES_USE_SSL = False
ES_VERIFY_CERTS = False
ES_USER = None
ES_PASSWORD = None
ES_INDEX_NAME = "bgp_updates"
```

常见问题
- 如果 `docker compose up` 报内存或权限错误，请检查 Docker 守护进程允许的内存与 `vm.max_map_count`。  
- 如果希望启用 ES 安全（recommended for non-local), 请参考 Elastic 官方文档或使用托管服务（Elastic Cloud / AWS OpenSearch）。


